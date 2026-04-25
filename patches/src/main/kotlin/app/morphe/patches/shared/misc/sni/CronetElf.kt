package app.morphe.patches.shared.misc.sni

import app.morphe.patcher.patch.PatchException
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal data class ElfLoadSegment(
    val fileOffset: Long,
    val fileSize: Long,
    val virtualAddress: Long,
)

internal fun parseElfLoadSegments(bytes: ByteArray): List<ElfLoadSegment> {
    if (bytes.size < 0x40) {
        throw PatchException("Target library is too small to be a valid ELF64 binary")
    }

    if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte() ||
        bytes[4].toInt() != 2 || bytes[5].toInt() != 1
    ) {
        throw PatchException("Target library is not a little-endian ELF64 binary")
    }

    val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val programHeaderOffset = bb.getLong(0x20)
    val programHeaderEntrySize = bb.getShort(0x36).toInt() and 0xffff
    val programHeaderCount = bb.getShort(0x38).toInt() and 0xffff

    if (programHeaderOffset < 0 || programHeaderEntrySize <= 0 || programHeaderCount <= 0) {
        throw PatchException("ELF program header table is missing or malformed")
    }

    val segments = mutableListOf<ElfLoadSegment>()
    repeat(programHeaderCount) { index ->
        val entryOffset = programHeaderOffset + index.toLong() * programHeaderEntrySize
        if (entryOffset < 0 || entryOffset + programHeaderEntrySize > bytes.size.toLong()) {
            throw PatchException("ELF program header entry $index is out of bounds")
        }

        val base = entryOffset.toInt()
        val type = bb.getInt(base)
        if (type != 1) return@repeat

        val fileOffset = bb.getLong(base + 0x08)
        val virtualAddress = bb.getLong(base + 0x10)
        val fileSize = bb.getLong(base + 0x20)
        if (fileSize > 0) {
            segments += ElfLoadSegment(
                fileOffset = fileOffset,
                fileSize = fileSize,
                virtualAddress = virtualAddress,
            )
        }
    }

    if (segments.isEmpty()) {
        throw PatchException("ELF binary does not contain any PT_LOAD segments")
    }

    return segments
}

internal fun fileOffsetToVirtualAddress(
    fileOffset: Int,
    segments: List<ElfLoadSegment>,
): Long {
    val offset = fileOffset.toLong()
    val segment = segments.firstOrNull { candidate ->
        offset >= candidate.fileOffset && offset < candidate.fileOffset + candidate.fileSize
    } ?: throw PatchException("File offset 0x${fileOffset.toString(16)} is not covered by any PT_LOAD segment")

    return segment.virtualAddress + (offset - segment.fileOffset)
}

internal fun virtualAddressToFileOffset(
    virtualAddress: Long,
    segments: List<ElfLoadSegment>,
): Int? {
    val segment = segments.firstOrNull { candidate ->
        virtualAddress >= candidate.virtualAddress &&
                virtualAddress < candidate.virtualAddress + candidate.fileSize
    } ?: return null

    val offset = segment.fileOffset + (virtualAddress - segment.virtualAddress)
    return offset.toInt()
}

internal fun encodeAdr(
    register: Int,
    instructionVirtualAddress: Long,
    targetVirtualAddress: Long,
): Int {
    require(register in 0..31) { "Invalid ADR register: $register" }

    val delta = targetVirtualAddress - instructionVirtualAddress
    val minDelta = -(1 shl 20)
    val maxDelta = (1 shl 20) - 1
    if (delta < minDelta || delta > maxDelta) {
        throw PatchException("ADR target delta out of range: $delta")
    }

    val imm21 = delta and 0x1fffff
    val immlo = (imm21 and 0x3).toInt()
    val immhi = ((imm21 shr 2) and 0x7ffff).toInt()

    return 0x10000000 or (immlo shl 29) or (immhi shl 5) or register
}

internal fun encodeAdrp(
    register: Int,
    instructionVirtualAddress: Long,
    targetVirtualAddress: Long,
): Int {
    require(register in 0..31) { "Invalid ADRP register: $register" }

    val instructionPage = instructionVirtualAddress and -0x1000L
    val targetPage = targetVirtualAddress and -0x1000L
    val deltaPages = (targetPage - instructionPage) shr 12

    val minDelta = -(1 shl 20)
    val maxDelta = (1 shl 20) - 1
    if (deltaPages < minDelta || deltaPages > maxDelta) {
        throw PatchException("ADRP page delta out of range: $deltaPages")
    }

    val imm21 = deltaPages and 0x1fffff
    val immlo = (imm21 and 0x3).toInt()
    val immhi = ((imm21 shr 2) and 0x7ffff).toInt()

    return 0x90000000.toInt() or (immlo shl 29) or (immhi shl 5) or register
}

internal fun encodeAddImmediate(
    destinationRegister: Int,
    sourceRegister: Int,
    immediate: Int,
): Int {
    require(destinationRegister in 0..31) { "Invalid ADD destination register: $destinationRegister" }
    require(sourceRegister in 0..31) { "Invalid ADD source register: $sourceRegister" }
    require(immediate in 0..0xfff) { "ADD immediate out of range: $immediate" }

    return 0x91000000.toInt() or
            (immediate shl 10) or
            (sourceRegister shl 5) or
            destinationRegister
}

internal fun encodeMovz(
    register: Int,
    immediate: Int,
    is64Bit: Boolean = false,
): Int {
    require(register in 0..31) { "Invalid MOVZ register: $register" }
    require(immediate in 0..0xffff) { "MOVZ immediate out of range: $immediate" }

    val base = if (is64Bit) 0xD2800000.toInt() else 0x52800000
    return base or (immediate shl 5) or register
}

internal fun decodeBlTargetVirtualAddress(
    bytes: ByteArray,
    instructionFileOffset: Int,
    segments: List<ElfLoadSegment>,
): Long? {
    if (instructionFileOffset < 0 || instructionFileOffset + 4 > bytes.size) return null

    val instruction = ByteBuffer.wrap(bytes, instructionFileOffset, 4)
        .order(ByteOrder.LITTLE_ENDIAN)
        .int
    val opcode = instruction ushr 26
    if (opcode != 0b100101) return null

    var imm26 = instruction and 0x03ffffff
    if ((imm26 and (1 shl 25)) != 0) {
        imm26 = imm26 or (-1 shl 26)
    }

    val instructionVirtualAddress = fileOffsetToVirtualAddress(instructionFileOffset, segments)
    return instructionVirtualAddress + (imm26.toLong() shl 2)
}

internal fun encodeBl(
    instructionVirtualAddress: Long,
    targetVirtualAddress: Long,
): Int {
    val delta = targetVirtualAddress - instructionVirtualAddress
    if ((delta and 0x3L) != 0L) {
        throw PatchException("BL target delta is not instruction-aligned: $delta")
    }

    val imm26 = delta shr 2
    val minDelta = -(1 shl 25)
    val maxDelta = (1 shl 25) - 1
    if (imm26 < minDelta || imm26 > maxDelta) {
        throw PatchException("BL target delta out of range: $delta")
    }

    return 0x94000000.toInt() or (imm26.toInt() and 0x03ffffff)
}

internal fun Int.toLittleEndianBytes(): ByteArray {
    return byteArrayOf(
        (this and 0xff).toByte(),
        ((this ushr 8) and 0xff).toByte(),
        ((this ushr 16) and 0xff).toByte(),
        ((this ushr 24) and 0xff).toByte(),
    )
}
