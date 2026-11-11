package com.veil.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// A restrained violet-on-charcoal palette. The accent is used only for
// outgoing bubbles and the online dot, so the interface stays quiet.
private val Violet = Color(0xFF7C5CFF)
private val VioletDim = Color(0xFF2A2340)
private val Charcoal = Color(0xFF120F1C)
private val Slate = Color(0xFF1B1826)
private val Mist = Color(0xFFE6E2F5)

private val DarkScheme = darkColorScheme(
    primary = Violet,
    onPrimary = Color.White,
    primaryContainer = VioletDim,
    onPrimaryContainer = Mist,
    secondary = Color(0xFF9C8CFF),
    secondaryContainer = Color(0xFF241E36),
    onSecondaryContainer = Mist,
    background = Charcoal,
    onBackground = Mist,
    surface = Charcoal,
    onSurface = Mist,
    surfaceVariant = Slate,
    onSurfaceVariant = Color(0xFF9A93B0),
    error = Color(0xFFF87171),
)

private val LightScheme = lightColorScheme(
    primary = Violet,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE4DCFF),
    onPrimaryContainer = Color(0xFF1B1435),
    secondary = Color(0xFF5B48B8),
    secondaryContainer = Color(0xFFEDE8FF),
    onSecondaryContainer = Color(0xFF1B1435),
    background = Color(0xFFFAF9FE),
    onBackground = Color(0xFF16121F),
    surface = Color(0xFFFAF9FE),
    onSurface = Color(0xFF16121F),
    surfaceVariant = Color(0xFFEFECF7),
    onSurfaceVariant = Color(0xFF5A5470),
    error = Color(0xFFB3261E),
)

@Composable
fun VeilTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkScheme else LightScheme,
        content = content,
    )
}
