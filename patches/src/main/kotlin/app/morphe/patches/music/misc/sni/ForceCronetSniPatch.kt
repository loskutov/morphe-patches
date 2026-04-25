package app.morphe.patches.music.misc.sni

import app.morphe.patches.music.shared.Constants.COMPATIBILITY_YOUTUBE_MUSIC
import app.morphe.patches.shared.misc.sni.forceCronetSniPatch

@Suppress("unused")
val forceCronetSniPatchMusic = forceCronetSniPatch {
    compatibleWith(COMPATIBILITY_YOUTUBE_MUSIC)
}
