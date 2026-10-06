package com.msnguard.vpn

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView

/** Small in-app promotion for Younes's public news channels. */
object ParvazSocialLinks {
    private const val INSTAGRAM = "https://instagram.com/Nabz.moamma"
    private const val TELEGRAM = "https://t.me/NabzKhabarOfficial"

    fun build(activity: MainActivity): View = LinearLayout(activity).apply {
        fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(10), dp(16), dp(10))
        background = GradientDrawable().apply {
            cornerRadius = dp(18).toFloat()
            setColor(Color.argb(34, 79, 227, 193))
            setStroke(dp(1), Color.argb(80, 79, 227, 193))
        }
        addView(TextView(activity).apply {
            text = "خبرهای پرواز"
            setTextColor(Color.WHITE)
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(activity).apply {
            text = "برای خبرهای جدید ما را دنبال کنید"
            setTextColor(Color.LTGRAY)
            textSize = 12f
            setPadding(0, dp(2), 0, dp(7))
        })
        addView(row(activity, "اینستاگرام  @Nabz.moamma", INSTAGRAM, dp(34)))
        addView(row(activity, "تلگرام  NabzKhabarOfficial", TELEGRAM, dp(34)))
    }.also { card ->
        card.isFocusable = true
        card.contentDescription = "لینک‌های شبکه‌های اجتماعی پرواز"
    }

    private fun row(activity: MainActivity, title: String, url: String, height: Int) = TextView(activity).apply {
        text = title
        textSize = 13f
        setTextColor(Color.rgb(159, 255, 228))
        gravity = Gravity.CENTER_VERTICAL
        minHeight = height
        isClickable = true
        isFocusable = true
        setOnClickListener {
            activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        }
    }
}
