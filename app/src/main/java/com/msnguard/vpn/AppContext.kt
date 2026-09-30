package com.msnguard.vpn

import android.content.Context

object AppContext {
    @Volatile private var ctx: Context? = null
    fun set(c: Context) { ctx = c.applicationContext }
    fun get(): Context? = ctx
}
