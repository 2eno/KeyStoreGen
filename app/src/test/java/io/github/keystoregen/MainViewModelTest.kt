package io.github.keystoregen

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MainViewModelTest {
    private fun path(input: String) = MainViewModel().apply { repository = input }.repositoryPath

    @Test
    fun repositoryAcceptsUrlsRemotesAndPaths() {
        assertEquals("owner/repo", path("owner/repo"))
        assertEquals("owner/repo", path("https://github.com/owner/repo"))
        assertEquals("owner/repo", path("https://github.com/owner/repo/"))
        assertEquals("owner/my.repo", path("git@github.com:owner/my.repo.git"))
        assertNull(path(""))
        assertNull(path("just-a-name"))
    }

    @Test
    fun secretPrefixes() {
        assertEquals("KEYSTORE_ALIAS_PASSWORD", SecretNames().aliasPassword)
        assertEquals("WEAR_KEYSTORE", SecretNames("WEAR_").keystore)
        assertEquals(false, SecretNames.isValidPrefix("1A"))
        assertEquals(false, SecretNames.isValidPrefix("A-B"))
    }
}
