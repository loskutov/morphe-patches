package app.morphe.patches.shared.misc.sni

import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.ResourcePatchBuilder
import app.morphe.patcher.patch.resourcePatch
import app.morphe.patcher.patch.stringOption
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs

private const val ARM64_DIR = "lib/arm64-v8a"
private const val DEFAULT_FORCED_SNI_HOST = "kek.bdn.dev"
private const val HTTPS_PORT = 443
private const val HOST_PORT_PAIR_SIZE = 0x20
private const val HOST_PORT_PAIR_PORT_OFFSET = 0x00
private const val HOST_PORT_PAIR_HOST_OFFSET = 0x08
private const val SHORT_STRING_SIZE_OFFSET = HOST_PORT_PAIR_HOST_OFFSET + 0x17
private const val MAX_SHORT_STRING_HOST_LENGTH = 22
private val HOSTNAME_REGEX = Regex("^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")

// Source-level context:
// - SSLConnectJob::DoSSLConnect() first completes the nested TransportConnectJob
//   and obtains a connected StreamSocket.
// - It then calls CreateSSLClientSocket(..., std::move(nested_socket_),
//   params_->host_and_port(), ssl_config).
//
// This is the clean boundary between the lower transport endpoint and the TLS
// authentication hostname. The fingerprint below matches the call-site tail
// where x3 is loaded with params_->host_and_port(). We only replace that x3
// argument with a synthetic HostPortPair stored in an RX cave; the underlying
// connected stream socket keeps using the original endpoint.
private val TLS_HOST_ARGUMENT_FINGERPRINT_BYTES = byteArrayOf(
    0x43, 0x61, 0x00, 0x91.toByte(), // add x3, x10, #0x18
    0x08, 0x00, 0x40, 0xf9.toByte(), // ldr x8, [x0]
    0x09, 0x11, 0x80.toByte(), 0xb9.toByte(), // ldrsw x9, [x8, #0x10]
    0x08, 0x01, 0x09, 0x8b.toByte(), // add x8, x8, x9
    0x00, 0x01, 0x3f, 0xd6.toByte(), // blr x8
)

private const val TLS_HOST_ARGUMENT_INSTRUCTION_OFFSET = 0
private const val BRK_MASK = 0xffe0001f.toInt()
private const val BRK_OPCODE = 0xd4200000.toInt()

private fun ByteArray.findAll(needle: ByteArray): List<Int> {
    if (needle.isEmpty() || size < needle.size) return emptyList()

    val matches = mutableListOf<Int>()
    for (index in 0..(size - needle.size)) {
        if (this[index] != needle[0]) continue

        var matched = true
        for (i in 1 until needle.size) {
            if (this[index + i] != needle[i]) {
                matched = false
                break
            }
        }

        if (matched) {
            matches += index
        }
    }

    return matches
}

private fun alignUp(value: Int, alignment: Int): Int {
    return (value + alignment - 1) and -alignment
}

private fun ByteArray.readIntLE(offset: Int): Int {
    return ByteBuffer.wrap(this, offset, Int.SIZE_BYTES)
        .order(ByteOrder.LITTLE_ENDIAN)
        .int
}

private fun decodeDirectBranchTarget(
    instruction: Int,
    instructionFileOffset: Int,
    loadSegments: List<ElfLoadSegment>,
): Int? {
    // Check if instruction offset is within a PT_LOAD segment
    val offsetLong = instructionFileOffset.toLong()
    val isInLoadSegment = loadSegments.any { segment ->
        offsetLong >= segment.fileOffset && offsetLong < segment.fileOffset + segment.fileSize
    }
    if (!isInLoadSegment) return null

    val instructionVirtualAddress = fileOffsetToVirtualAddress(instructionFileOffset, loadSegments)

    val targetVirtualAddress = when {
        instruction ushr 26 == 0b000101 || instruction ushr 26 == 0b100101 -> {
            var imm26 = instruction and 0x03ffffff
            if ((imm26 and (1 shl 25)) != 0) {
                imm26 = imm26 or (-1 shl 26)
            }
            instructionVirtualAddress + (imm26.toLong() shl 2)
        }

        instruction and 0xff000010.toInt() == 0x54000000 -> {
            var imm19 = (instruction ushr 5) and 0x7ffff
            if ((imm19 and (1 shl 18)) != 0) {
                imm19 = imm19 or (-1 shl 19)
            }
            instructionVirtualAddress + (imm19.toLong() shl 2)
        }

        instruction and 0x7e000000 == 0x34000000 -> {
            var imm19 = (instruction ushr 5) and 0x7ffff
            if ((imm19 and (1 shl 18)) != 0) {
                imm19 = imm19 or (-1 shl 19)
            }
            instructionVirtualAddress + (imm19.toLong() shl 2)
        }

        instruction and 0x7e000000 == 0x36000000 -> {
            var imm14 = (instruction ushr 5) and 0x3fff
            if ((imm14 and (1 shl 13)) != 0) {
                imm14 = imm14 or (-1 shl 14)
            }
            instructionVirtualAddress + (imm14.toLong() shl 2)
        }

        else -> return null
    }

    return virtualAddressToFileOffset(targetVirtualAddress, loadSegments)
}

private fun collectDirectBranchTargets(
    bytes: ByteArray,
    loadSegments: List<ElfLoadSegment>,
): Set<Int> {
    val targets = mutableSetOf<Int>()
    for (offset in 0..(bytes.size - Int.SIZE_BYTES) step Int.SIZE_BYTES) {
        decodeDirectBranchTarget(bytes.readIntLE(offset), offset, loadSegments)?.let(targets::add)
    }
    return targets
}

private fun findSyntheticHostPortPairCave(
    bytes: ByteArray,
    patchOffset: Int,
    loadSegments: List<ElfLoadSegment>,
): Int {
    val branchTargets = collectDirectBranchTargets(bytes, loadSegments)
    val patchVirtualAddress = fileOffsetToVirtualAddress(patchOffset, loadSegments)

    // First try the original BRK-based approach
    for (offset in 0..(bytes.size - HOST_PORT_PAIR_SIZE - Int.SIZE_BYTES) step Int.SIZE_BYTES) {
        val instruction = bytes.readIntLE(offset)
        if (instruction and BRK_MASK != BRK_OPCODE) continue

        val caveOffset = alignUp(offset + Int.SIZE_BYTES, Long.SIZE_BYTES)
        if (caveOffset + HOST_PORT_PAIR_SIZE > bytes.size) continue

        // Check if caveOffset is within a PT_LOAD segment before proceeding
        val caveOffsetLong = caveOffset.toLong()
        val isInLoadSegment = loadSegments.any { segment ->
            caveOffsetLong >= segment.fileOffset && caveOffsetLong < segment.fileOffset + segment.fileSize
        }
        if (!isInLoadSegment) continue

        val caveVirtualAddress = fileOffsetToVirtualAddress(caveOffset, loadSegments)
        if (abs(caveVirtualAddress - patchVirtualAddress) >= (1L shl 20)) continue

        val caveRange = caveOffset until caveOffset + HOST_PORT_PAIR_SIZE
        if (branchTargets.any { it in caveRange }) continue

        println("DEBUG: Found BRK-based cave at 0x${caveOffset.toString(16)}")
        return caveOffset
    }

    // Fallback: look for any aligned location within PT_LOAD segments that's not a branch target
    println("DEBUG: No BRK-based cave found, trying fallback approach")
    for (segment in loadSegments) {
        val segmentStart = segment.fileOffset.toInt()
        val segmentEnd = (segment.fileOffset + segment.fileSize).toInt() - HOST_PORT_PAIR_SIZE

        for (caveOffset in segmentStart..segmentEnd step 8) {  // Try 8-byte aligned positions
            val caveVirtualAddress = fileOffsetToVirtualAddress(caveOffset, loadSegments)
            if (abs(caveVirtualAddress - patchVirtualAddress) >= (1L shl 20)) continue

            val caveRange = caveOffset until caveOffset + HOST_PORT_PAIR_SIZE
            if (branchTargets.any { it in caveRange }) continue

            // Check if this area looks like it might be padding/unused (all zeros or NOPs)
            val isPadding = caveRange.all { offset ->
                val value = if (offset + 3 < bytes.size) bytes.readIntLE(offset) else 0
                value == 0 || value == 0xD503201F.toInt()  // NOP instruction
            }

            if (isPadding) {
                println("DEBUG: Found padding-based cave at 0x${caveOffset.toString(16)}")
                return caveOffset
            }
        }
    }

    throw PatchException("No suitable RX cave found for synthetic HostPortPair")
}

private fun buildSyntheticHostPortPair(host: String): ByteArray {
    require(host.length <= MAX_SHORT_STRING_HOST_LENGTH) {
        "Host '$host' is too long for libc++ short-string HostPortPair storage"
    }

    return ByteArray(HOST_PORT_PAIR_SIZE).also { bytes ->
        val hostBytes = host.encodeToByteArray()
        hostBytes.copyInto(bytes, destinationOffset = HOST_PORT_PAIR_HOST_OFFSET)
        bytes[HOST_PORT_PAIR_HOST_OFFSET + hostBytes.size] = 0
        bytes[SHORT_STRING_SIZE_OFFSET] = hostBytes.size.toByte()
        bytes[HOST_PORT_PAIR_PORT_OFFSET] = (HTTPS_PORT and 0xff).toByte()
        bytes[HOST_PORT_PAIR_PORT_OFFSET + 1] = ((HTTPS_PORT ushr 8) and 0xff).toByte()
    }
}

private fun chooseCronetLibrary(arm64Dir: File): File? {
    val candidates = arm64Dir.listFiles()
        ?.filter { file ->
            file.isFile && file.name.startsWith("libcronet") && file.name.endsWith(".so")
        }
        ?.sortedBy { it.name }
        .orEmpty()

    return when (candidates.size) {
        0 -> null
        1 -> candidates.single()
        else -> throw PatchException(
            "Expected exactly one libcronet*.so in '$ARM64_DIR', found: " +
                    candidates.joinToString { it.name }
        )
    }
}

internal fun forceCronetSniPatch(
    block: ResourcePatchBuilder.() -> Unit,
) = resourcePatch(
    name = "Force Cronet SNI (arm64)",
    description = "Patches bundled arm64 libcronet so TLS SNI is forced to a configurable hostname in " +
            "the SSLClientSocket path. URL and HTTP Host remain unchanged.",
    default = false,
) {
    block()

    val forcedSniHost by stringOption(
        key = "forcedSniHost",
        default = DEFAULT_FORCED_SNI_HOST,
        title = "Forced SNI hostname",
        description = "Hostname written into libcronet and used by the SSLClientSocket path for TLS SNI.",
        required = true,
    ) {
        it != null && HOSTNAME_REGEX.matches(it)
    }

    execute {
        val forcedSniHostValue = forcedSniHost!!.trim()
        if (forcedSniHostValue.length > MAX_SHORT_STRING_HOST_LENGTH) {
            throw PatchException(
                "Forced SNI host '$forcedSniHostValue' is too long. " +
                        "Maximum supported length is $MAX_SHORT_STRING_HOST_LENGTH characters."
            )
        }

        val arm64Dir = get(ARM64_DIR)
        if (!arm64Dir.exists() || !arm64Dir.isDirectory) {
            throw PatchException("Missing '$ARM64_DIR' in target APK")
        }

        val cronetLib = chooseCronetLibrary(arm64Dir)
            ?: throw PatchException("No libcronet*.so found in '$ARM64_DIR'")

        val bytes = cronetLib.readBytes()
        val loadSegments = parseElfLoadSegments(bytes)
        val expected = TLS_HOST_ARGUMENT_FINGERPRINT_BYTES

        val patchOffsets = bytes.findAll(expected)
        if (patchOffsets.isEmpty()) {
            throw PatchException("TLS host argument fingerprint not found in ${cronetLib.name}.")
        }
        if (patchOffsets.size > 1) {
            println("WARNING: TLS host argument fingerprint matched multiple locations: " +
                    patchOffsets.joinToString { "0x${it.toString(16)}" })
            println("Using first match: 0x${patchOffsets.first().toString(16)}")
        }

        val patchOffset = patchOffsets.first() + TLS_HOST_ARGUMENT_INSTRUCTION_OFFSET
        println("DEBUG: Using patch offset: 0x${patchOffset.toString(16)}")

        val caveOffset = findSyntheticHostPortPairCave(
            bytes = bytes,
            patchOffset = patchOffset,
            loadSegments = loadSegments,
        )
        println("DEBUG: Found cave at offset: 0x${caveOffset.toString(16)}")

        val caveVirtualAddress = fileOffsetToVirtualAddress(caveOffset, loadSegments)
        val patchVirtualAddress = fileOffsetToVirtualAddress(patchOffset, loadSegments)

        val syntheticHostPortPair = buildSyntheticHostPortPair(forcedSniHostValue)
        println("DEBUG: Placing synthetic HostPortPair at 0x${caveOffset.toString(16)}: ${forcedSniHostValue}")
        syntheticHostPortPair.copyInto(bytes, destinationOffset = caveOffset)

        // Replace `add x3, x10, #0x18` (`params_->host_and_port()`) at the
        // SSLConnectJob boundary with `adr x3, <synthetic HostPortPair>`. The
        // nested StreamSocket has already connected to the original endpoint;
        // only the TLS hostname argument is redirected.
        val adrInstruction = encodeAdr(
            register = 3,
            instructionVirtualAddress = patchVirtualAddress,
            targetVirtualAddress = caveVirtualAddress,
        )
        println("DEBUG: Patching instruction at 0x${patchOffset.toString(16)}: 0x${adrInstruction.toString(16)}")
        adrInstruction.toLittleEndianBytes().copyInto(bytes, destinationOffset = patchOffset)

        cronetLib.writeBytes(bytes)
    }
}
