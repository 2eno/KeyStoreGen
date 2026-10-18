package io.github.keystoregen

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import io.github.keystoregen.ui.App
import io.github.keystoregen.ui.theme.KeyStoreGenTheme

/** A FragmentActivity because BiometricPrompt runs in a fragment. */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Passwords and keys are on screen: keep them out of screenshots and the recents preview.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            KeyStoreGenTheme {
                App()
            }
        }
    }
}
