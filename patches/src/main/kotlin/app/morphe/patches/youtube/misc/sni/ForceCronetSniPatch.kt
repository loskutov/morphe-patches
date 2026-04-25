package app.morphe.patches.youtube.misc.sni

import app.morphe.patches.shared.misc.sni.forceCronetSniPatch
import app.morphe.patches.youtube.shared.Constants.COMPATIBILITY_YOUTUBE

@Suppress("unused")
val forceCronetSniPatchYouTube = forceCronetSniPatch {
    compatibleWith(COMPATIBILITY_YOUTUBE)
}
