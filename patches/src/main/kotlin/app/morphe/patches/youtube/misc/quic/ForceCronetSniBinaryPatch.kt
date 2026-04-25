package app.morphe.patches.youtube.misc.quic

import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.resourcePatch
import app.morphe.patcher.patch.stringOption
import app.morphe.patches.youtube.shared.Constants.COMPATIBILITY_YOUTUBE
import java.io.File

private const val ARM64_DIR = "lib/arm64-v8a"
private const val REPLACEMENT_HOST_SLOT = ".example.com"
private const val DEFAULT_FORCED_SNI_HOST = "kek.bdn.dev"
private val HOSTNAME_REGEX = Regex("^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")
// Source-level context for the matched native block:
// - Chromium net/socket/ssl_client_socket_impl.cc keeps the destination host in
//   `SSLClientSocketImpl::host_and_port_` and later consumes it in `Init()` for
//   `HostIsIPAddressNoBrackets(host_and_port_.host())` and
//   `SSL_set_tlsext_host_name(ssl_.get(), host_and_port_.host().c_str())`.
// - The broader goal here is to rewrite that stored host early enough that the
//   same spoofed name is reused by later SSLClientSocketImpl paths, rather than
//   only patching the single SSL_set_tlsext_host_name(...) call argument.
//
// The anchor below still keys off the original `c_str()` materialization right
// before SSL_set_tlsext_host_name(...), then rewinds to replace the whole block.
private const val HOST_OVERRIDE_BLOCK_START_DELTA = 0x34
private const val HOST_OVERRIDE_BLOCK_LENGTH = 0x44
private const val HOST_SETTER_CALL_DELTA = 0x0c
private const val HOST_REPLACEMENT_CALL_DELTA = 0x20
private const val NOP = 0xD503201F.toInt()
private const val LDP_X1_X2_X0 = 0xA9400801.toInt()
private const val STP_X1_X2_X19_0X128 = 0xA9128A61.toInt()
private const val STRB_W8_X19_0X13F = 0x3904FE68.toInt()
private const val LDR_X0_X19_0X108 = 0xF9408660.toInt()
private const val ADD_X1_X19_0X128 = 0x9104A261.toInt()

// The original anchor is the instruction triplet that materializes
// `host_and_port_.host().c_str()` for SSL_set_tlsext_host_name(...).
// We keep matching this location because it has been stable across the tested
// Cronet builds and sits inside the same block that reads `host_and_port_`.
private val SNI_FINGERPRINT_BYTES = byteArrayOf(
    0x48,
    0x00,
    0xf8.toByte(),
    0x36,
    0x94.toByte(),
    0x02,
    0x40,
    0xf9.toByte(),
    0xe1.toByte(),
    0x03,
    0x14,
    0xaa.toByte(),
)
private val REPLACEMENT_HOST_SLOT_BYTES = "$REPLACEMENT_HOST_SLOT\u0000".encodeToByteArray()

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

@Suppress("unused")
val forceCronetSniBinaryPatch = resourcePatch(
    name = "Force Cronet SNI (arm64)",
    description = "Patches bundled arm64 libcronet so TLS SNI is forced to a configurable hostname in " +
            "the SSLClientSocket path. URL and HTTP Host remain unchanged.",
    default = false,
) {
    compatibleWith(COMPATIBILITY_YOUTUBE)

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
        val forcedSniHostBytes = "$forcedSniHostValue\u0000".encodeToByteArray()

        val arm64Dir = get(ARM64_DIR)
        if (!arm64Dir.exists() || !arm64Dir.isDirectory) {
            throw PatchException("Missing '$ARM64_DIR' in target APK")
        }

        val cronetLib = chooseCronetLibrary(arm64Dir)
            ?: throw PatchException("No libcronet*.so found in '$ARM64_DIR'")

        val bytes = cronetLib.readBytes()
        val expected = SNI_FINGERPRINT_BYTES

        val patchOffsets = bytes.findAll(expected)
        if (patchOffsets.size != 1) {
            throw PatchException(
                if (patchOffsets.isEmpty()) {
                    "SNI fingerprint not found in ${cronetLib.name}."
                } else {
                    "SNI fingerprint matched multiple locations in ${cronetLib.name}: " +
                            patchOffsets.joinToString { "0x${it.toString(16)}" }
                }
            )
        }

        val hostOffsets = bytes.findAll(REPLACEMENT_HOST_SLOT_BYTES)
        if (hostOffsets.size != 1) {
            throw PatchException(
                if (hostOffsets.isEmpty()) {
                    "Host string slot '$REPLACEMENT_HOST_SLOT' not found in ${cronetLib.name}"
                } else {
                    "Host string slot '$REPLACEMENT_HOST_SLOT' matched multiple locations in ${cronetLib.name}: " +
                            hostOffsets.joinToString { "0x${it.toString(16)}" }
                }
            )
        }

        val patchOffset = patchOffsets.single()
        val hostOffset = hostOffsets.single()
        val loadSegments = parseElfLoadSegments(bytes)
        val patchStartOffset = patchOffset - HOST_OVERRIDE_BLOCK_START_DELTA
        if (patchStartOffset < 0) {
            throw PatchException("Patch start is out of bounds in ${cronetLib.name}")
        }

        val setterCallOffset = patchOffset + HOST_SETTER_CALL_DELTA
        val setterVirtualAddress = decodeBlTargetVirtualAddress(
            bytes = bytes,
            instructionFileOffset = setterCallOffset,
            segments = loadSegments,
        ) ?: throw PatchException(
            "Expected BL instruction at 0x${setterCallOffset.toString(16)} in ${cronetLib.name}"
        )

        val patchStartVirtualAddress = fileOffsetToVirtualAddress(patchStartOffset, loadSegments)
        val hostVirtualAddress = fileOffsetToVirtualAddress(hostOffset, loadSegments)
        val hostLength = forcedSniHostValue.length

        val adrpX0 = encodeAdrp(
            register = 0,
            instructionVirtualAddress = patchStartVirtualAddress,
            targetVirtualAddress = hostVirtualAddress,
        )
        val addX0X0 = encodeAddImmediate(
            destinationRegister = 0,
            sourceRegister = 0,
            immediate = (hostVirtualAddress and 0xfff).toInt(),
        )
        val blSetter = encodeBl(
            instructionVirtualAddress = patchStartVirtualAddress + HOST_REPLACEMENT_CALL_DELTA,
            targetVirtualAddress = setterVirtualAddress,
        )
        val movW8HostLength = encodeMovz(
            register = 8,
            immediate = hostLength,
            is64Bit = false,
        )

        if (forcedSniHostBytes.size > REPLACEMENT_HOST_SLOT_BYTES.size) {
            throw PatchException(
                "Replacement host '$forcedSniHostValue' does not fit in existing string slot for '$REPLACEMENT_HOST_SLOT'"
            )
        }

        REPLACEMENT_HOST_SLOT_BYTES.indices.forEach { index ->
            bytes[hostOffset + index] = 0
        }
        forcedSniHostBytes.copyInto(bytes, destinationOffset = hostOffset)

        // Overwrite the inline libc++ short-string storage for
        // `SSLClientSocketImpl::host_and_port_.host()` with the replacement SNI
        // hostname before Init() reaches its hostname-dependent logic. The
        // backing string literal itself is replaced in-place inside libcronet,
        // reusing the existing `.example.com\0` slot because
        // the configured hostname is expected to fit into that slot.
        // before Init() reaches its hostname-dependent logic. The short-string
        // size byte lives at +0x17 of the 24-byte std::string object, which is
        // why we update `[x19 + 0x13f]` after copying the 16-byte payload.
        val replacementWords = mutableListOf(
            adrpX0,
            addX0X0,
            LDP_X1_X2_X0,
            STP_X1_X2_X19_0X128,
            movW8HostLength,
            STRB_W8_X19_0X13F,
            LDR_X0_X19_0X108,
            ADD_X1_X19_0X128,
            blSetter,
        )
        while (replacementWords.size * Int.SIZE_BYTES < HOST_OVERRIDE_BLOCK_LENGTH) {
            replacementWords += NOP
        }

        val replacement = replacementWords
            .flatMap { it.toLittleEndianBytes().asIterable() }
            .toByteArray()

        replacement.copyInto(bytes, destinationOffset = patchStartOffset)

        cronetLib.writeBytes(bytes)
    }
}
