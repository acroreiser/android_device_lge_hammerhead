#
# Copyright (C) 2013 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This file includes all definitions that apply to ALL hammerhead devices, and
# are also specific to hammerhead devices
#
# Everything in this directory will become public

# Soong namespaces
PRODUCT_SOONG_NAMESPACES += \
    $(LOCAL_PATH) \
    hardware/broadcom/libbt

# Public Libraries
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/public.libraries.txt:$(TARGET_COPY_OUT_VENDOR)/etc/public.libraries.txt

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/init.hammerhead.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.hammerhead.rc \
    $(LOCAL_PATH)/init.hammerhead.usb.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.hammerhead.usb.rc \
    $(LOCAL_PATH)/init.recovery.hammerhead.rc:$(TARGET_COPY_OUT_RECOVERY)/root/init.recovery.hammerhead.rc \
    $(LOCAL_PATH)/fstab.hammerhead:$(TARGET_COPY_OUT_RAMDISK)/fstab.hammerhead \
    $(LOCAL_PATH)/fstab.hammerhead:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.hammerhead \
    $(LOCAL_PATH)/ueventd.hammerhead.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc

PRODUCT_PACKAGES += \
    init.post_boot.sh

# Input device files for hammerhead
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/gpio-keys.kl:$(TARGET_COPY_OUT_VENDOR)/usr/keylayout/gpio-keys.kl \
    $(LOCAL_PATH)/gpio-keys.kcm:$(TARGET_COPY_OUT_VENDOR)/usr/keychars/gpio-keys.kcm \
    $(LOCAL_PATH)/qpnp_pon.kl:$(TARGET_COPY_OUT_VENDOR)/usr/keylayout/qpnp_pon.kl \
    $(LOCAL_PATH)/qpnp_pon.kcm:$(TARGET_COPY_OUT_VENDOR)/usr/keychars/qpnp_pon.kcm \
    $(LOCAL_PATH)/Button_Jack.kl:$(TARGET_COPY_OUT_VENDOR)/usr/keylayout/msm8974-taiko-mtp-snd-card_Button_Jack.kl \
    $(LOCAL_PATH)/Button_Jack.kcm:$(TARGET_COPY_OUT_VENDOR)/usr/keychars/msm8974-taiko-mtp-snd-card_Button_Jack.kcm \
    $(LOCAL_PATH)/hs_detect.kl:$(TARGET_COPY_OUT_VENDOR)/usr/keylayout/hs_detect.kl \
    $(LOCAL_PATH)/hs_detect.kcm:$(TARGET_COPY_OUT_VENDOR)/usr/keychars/hs_detect.kcm

# Prebuilt input device calibration files
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/touch_dev.idc:$(TARGET_COPY_OUT_VENDOR)/usr/idc/touch_dev.idc

PRODUCT_COPY_FILES += \
    frameworks/av/services/audiopolicy/config/bluetooth_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/usb_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml \
    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
    $(LOCAL_PATH)/audio_platform_info.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_platform_info.xml \
    $(LOCAL_PATH)/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
    $(LOCAL_PATH)/mixer_paths.xml:$(TARGET_COPY_OUT_VENDOR)/etc/mixer_paths.xml

PRODUCT_COPY_FILES += \
    frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_telephony.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_video_le.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_video_le.xml \
    $(LOCAL_PATH)/media_codecs.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs.xml \
    $(LOCAL_PATH)/media_codecs_performance.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance.xml \
    $(LOCAL_PATH)/media_profiles_V1_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_V1_0.xml

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/handheld_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/handheld_core_hardware.xml \
    frameworks/native/data/etc/android.hardware.camera.flash-autofocus.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.flash-autofocus.xml \
    frameworks/native/data/etc/android.hardware.camera.front.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.front.xml \
    frameworks/native/data/etc/android.hardware.camera.full.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.full.xml \
    frameworks/native/data/etc/android.hardware.camera.raw.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.raw.xml \
    frameworks/native/data/etc/android.hardware.location.gps.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.location.gps.xml \
    frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.xml \
    frameworks/native/data/etc/android.hardware.wifi.direct.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.direct.xml \
    frameworks/native/data/etc/android.hardware.sensor.proximity.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.proximity.xml \
    frameworks/native/data/etc/android.hardware.sensor.light.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.light.xml \
    frameworks/native/data/etc/android.hardware.sensor.gyroscope.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.gyroscope.xml \
    frameworks/native/data/etc/android.hardware.sensor.barometer.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.barometer.xml \
    frameworks/native/data/etc/android.hardware.sensor.stepcounter.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.stepcounter.xml \
    frameworks/native/data/etc/android.hardware.sensor.stepdetector.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.stepdetector.xml \
    frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml \
    frameworks/native/data/etc/android.software.sip.voip.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.sip.voip.xml \
    frameworks/native/data/etc/android.software.ipsec_tunnels.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.ipsec_tunnels.xml \
    frameworks/native/data/etc/android.hardware.usb.accessory.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.accessory.xml \
    frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml \
    frameworks/native/data/etc/android.hardware.telephony.gsm.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.telephony.gsm.xml \
    frameworks/native/data/etc/android.hardware.telephony.ims.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.telephony.ims.xml \
    frameworks/native/data/etc/android.hardware.audio.low_latency.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.audio.low_latency.xml \
    frameworks/native/data/etc/android.hardware.bluetooth_le.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.bluetooth_le.xml \
    frameworks/native/data/etc/android.hardware.telephony.cdma.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.telephony.cdma.xml \
    frameworks/native/data/etc/android.software.midi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.midi.xml

# IMS over Wi-Fi data service and network qualification service.
PRODUCT_PACKAGES += \
    Iwlan \
    QualifiedNetworksService \
    PhhIms \
    CarrierConfigOverlay

PRODUCT_PROPERTY_OVERRIDES += \
    persist.dbg.volte_avail_ovr=1 \
    persist.dbg.wfc_avail_ovr=1 \
    persist.dbg.allow_ims_off=1

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/permissions/privapp-permissions-me.phh.ims.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/privapp-permissions-me.phh.ims.xml

# For GPS
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/sec_config:$(TARGET_COPY_OUT_VENDOR)/etc/sec_config

# NFC access control + feature files + configuration
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.xml \
    frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.nfc.hce.xml \
    $(LOCAL_PATH)/nfc/libnfc-nci.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nci.conf \
    $(LOCAL_PATH)/nfc/libnfc-nci-20791b05.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nci-20791b05.conf

# Privapp Whitelist
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/permissions/privapp-permissions-hammerhead.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/privapp-permissions-hammerhead.xml

PRODUCT_AAPT_CONFIG := normal
PRODUCT_AAPT_PREF_CONFIG := xxhdpi
PRODUCT_CHARACTERISTICS := nosdcard

PRODUCT_DEXPREOPT_SPEED_APPS += SystemUIGo \
    Settings \
    TeleService \
    PhhIms \
    Dialer \
    Contacts \
    messaging \
    DocumentsUI \
    CredentialManager \
    Aperture \
    Glimpse \
    Twelve \
    Etar \
    StorageManager

PRODUCT_DISABLE_SCUDO := true
PRODUCT_ENFORCE_VINTF_MANIFEST_OVERRIDE := true
PRODUCT_BROKEN_VERIFY_USES_LIBRARIES := true

DEVICE_PACKAGE_OVERLAYS := \
    $(LOCAL_PATH)/overlay

# Enforced RRO targets
PRODUCT_ENFORCE_RRO_TARGETS := *
PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += \
    $(LOCAL_PATH)/overlay-lineage/lineage-sdk

PRODUCT_PACKAGES += \
    SystemUIGo

PRODUCT_PACKAGES += \
    android.hardware.wifi-service-lazy \
    libwpa_client \
    hostapd \
    wificond \
    wpa_supplicant \
    wpa_supplicant.conf \
    iw_vendor \
    wireless-regdomain.sh

# Overlays for Wifi and Tethering configuration
PRODUCT_PACKAGES += \
    WifiOverlay \
    TetheringConfigOverlay

PRODUCT_PACKAGES += \
    audio.bluetooth.default \
    android.hardware.bluetooth.audio@2.0-impl \
    android.hardware.bluetooth@1.0-impl \
    android.hardware.bluetooth@1.0-service \
    libbt-vendor

$(call soong_config_set,brcm_libbt,custom_bt_config,//device/lge/hammerhead:vnd_hammerhead.txt)
$(call soong_config_set,brcm_libbt,bdroid_buildcfg_include_dir,device/lge/hammerhead/bluetooth/configs)

# ConfigStore
PRODUCT_PACKAGES += \
    disable_configstore

# LiveDisplay
PRODUCT_PACKAGES += \
    vendor.lineage.livedisplay-service.sysfs

$(call soong_config_set_bool,livedisplay_sysfs,enable_dcc,true)

# TimeKeep
PRODUCT_PACKAGES += \
    timekeep \
    TimeKeep

PRODUCT_PACKAGES += \
    android.hardware.graphics.allocator@2.0-impl \
    android.hardware.graphics.allocator@2.0-service \
    android.hardware.graphics.composer@2.1-service \
    android.hardware.graphics.mapper@2.0-impl-2.1 \
    android.hardware.memtrack@1.0-impl \
    android.hardware.memtrack@1.0-service \
    gralloc.msm8974 \
    hwcomposer.msm8974 \
    memtrack.msm8974 \
    libqdutils \
    libqdMetaData \
    libui.vendor

# RenderScript HAL
PRODUCT_PACKAGES += \
    android.hardware.renderscript@1.0-impl

PRODUCT_PACKAGES += \
    libc2dcolorconvert \
    libminijail:32 \
    libstagefrighthw \
    libOmxCore \
    libmm-omxcore \
    libOmxVdec \
    libOmxVenc

# Audio
PRODUCT_PACKAGES += \
    android.hardware.audio@7.1-impl \
    android.hardware.audio.service.hh \
    audio.primary.msm8974 \
    audio.usb.default \
    audio.r_submix.default \
    libaudio-resampler \
    libaudioroute

# Audio effects
PRODUCT_PACKAGES += \
    android.hardware.audio.effect@7.0-impl \
    libqcomvisualizer \
    libqcompostprocbundle

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml


# Audio package for Go
$(call inherit-product, frameworks/base/data/sounds/AudioPackageGo.mk)

# Camera
PRODUCT_PACKAGES += \
    android.hardware.camera.provider-service.lineage \
    libqomx_core \
    camera.device@3.2-impl \
    libmmcamera_interface \
    libmmjpeg_interface \
    camera.hammerhead \
    Aperture

PRODUCT_PACKAGES += \
    android.hardware.keymaster@4.1-service

# GPS configuration
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/gps/etc/flp.conf:$(TARGET_COPY_OUT_VENDOR)/etc/flp.conf \
    $(LOCAL_PATH)/gps/etc/gps.conf:$(TARGET_COPY_OUT_VENDOR)/etc/gps.conf \
    $(LOCAL_PATH)/gps/etc/izat.conf:$(TARGET_COPY_OUT_VENDOR)/etc/izat.conf \
    $(LOCAL_PATH)/gps/etc/sap.conf:$(TARGET_COPY_OUT_VENDOR)/etc/sap.conf

# GPS
PRODUCT_PACKAGES += \
    android.hardware.gnss@1.0-impl.hh \
    android.hardware.gnss@1.0-service.hh \
    libgps.utils \
    gps.msm8974

# Gatekeeper
PRODUCT_PACKAGES += \
    android.hardware.gatekeeper@1.0-service.software

# Health
PRODUCT_PACKAGES += \
    android.hardware.health@2.1-impl \
    android.hardware.health@2.1-service

# NFC packages
PRODUCT_PACKAGES += \
    android.hardware.nfc@1.0-impl-bcm \
    android.hardware.nfc@1.0-service \
    Tag

# Recorder
PRODUCT_PACKAGES += \
    Recorder

# Music player
PRODUCT_PACKAGES += \
    Twelve \
    AudioFX

# PDF reader
PRODUCT_PACKAGES += \
    Camelot

# Seccomp
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/seccomp/mediacodec.policy:$(TARGET_COPY_OUT_VENDOR)/etc/seccomp_policy/mediacodec.policy

# Vibrator HAL
PRODUCT_PACKAGES += \
    android.hardware.vibrator-service.hh

PRODUCT_PACKAGES += \
    libion

# Light HAL
PRODUCT_PACKAGES += \
    android.hardware.light-service.hh

PRODUCT_PACKAGES += \
    com.android.future.usb.accessory

# USB HAL service
PRODUCT_PACKAGES += \
    android.hardware.usb@1.3-service.basic

# Filesystem management tools
PRODUCT_PACKAGES += \
    e2fsck

# Power
PRODUCT_PACKAGES += \
    android.hardware.power-service.hh \
    android.hardware.power.stats-service.example \
    libpower.vendor \
    libsqlite.vendor

# libstdc++ for vendor blobs
PRODUCT_PACKAGES += \
    libstdc++_vendor

# Display
PRODUCT_PROPERTY_OVERRIDES += \
    debug.egl.hw=0 \
    ro.opengles.version=196608 \
    debug.egl.rive_workaround=1

PRODUCT_PROPERTY_OVERRIDES += \
    debug.hwui.renderer=opengl \
    debug.hwui.use_buffer_age=false

PRODUCT_PROPERTY_OVERRIDES += \
    debug.mdpcomp.logs=0 \
    persist.hwc.mdpcomp.enable=true

PRODUCT_PROPERTY_OVERRIDES += \
    debug.sf.disable_backpressure=1 \
    debug.sf.hw=0 \
    debug.sf.latch_unsignaled=0 \
    debug.sf.recomputecrop=0

PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.sf.color_saturation=1.0 \
    persist.sys.sf.disable_blurs=1 \
    ro.sf.blurs_are_expensive=1 \
    ro.sf.disable_triple_buffer=1 \
    sys.use_fifo_ui=1

# DRM
PRODUCT_PACKAGES += \
    android.hardware.drm@1.0-impl \
    android.hardware.drm@1.0-service \
    android.hardware.drm-service.clearkey

PRODUCT_PROPERTY_OVERRIDES += \
    drm.service.enabled=true

PRODUCT_PACKAGES += \
    android.hardware.sensors@1.0-impl \
    android.hardware.sensors@1.0-service

# Net
PRODUCT_PACKAGES += \
    netutils-wrapper-1.0 \
    libnetutils.vendor

PRODUCT_PACKAGES += \
    android.hardware.radio.config@1.1-service.hh \
    android.hardware.radio@1.4-service.hammerhead

# NTFS Filesystem
PRODUCT_PACKAGES += \
    fsck.ntfs \
    mkfs.ntfs \
    mount.ntfs

# Shims
PRODUCT_PACKAGES += \
    libshim_ril

# Set sensor streaming rate
PRODUCT_PROPERTY_OVERRIDES += \
    ro.qti.sensors.max_geomag_rotv=60 \
    ro.qti.sensors.max_gyro_rate=200 \
    ro.qti.sensors.max_accel_rate=200 \
    ro.qti.sensors.max_grav=200 \
    ro.qti.sensors.max_rotvec=200 \
    ro.qti.sensors.max_orient=200 \
    ro.qti.sensors.max_linacc=200 \
    ro.qti.sensors.max_gamerv_rate=200

# Enable optional sensor types
PRODUCT_PROPERTY_OVERRIDES += \
    ro.qti.sensors.smd=true \
    ro.qti.sensors.game_rv=true \
    ro.qti.sensors.georv=true \
    ro.qti.sensors.smgr_mag_cal_en=true \
    ro.qti.sensors.step_detector=true \
    ro.qti.sensors.step_counter=true \
    ro.qti.sensors.tap=false \
    ro.qti.sensors.facing=false \
    ro.qti.sensors.tilt=false \
    ro.qti.sensors.amd=false \
    ro.qti.sensors.rmd=false \
    ro.qti.sensors.vmd=false \
    ro.qti.sensors.pedometer=false \
    ro.qti.sensors.pam=false \
    ro.qti.sdk.sensors.gestures=false

# Enable some debug messages by default
PRODUCT_PROPERTY_OVERRIDES += \
    persist.debug.sensors.hal=w \
    debug.qualcomm.sns.daemon=w \
    debug.qualcomm.sns.libsensor1=w

# Ril sends only one RIL_UNSOL_CALL_RING, so set call_ring.multiple to false
PRODUCT_PROPERTY_OVERRIDES += \
    ro.telephony.call_ring.multiple=0

PRODUCT_PROPERTY_OVERRIDES += \
    wifi.interface=wlan0

PRODUCT_PROPERTY_OVERRIDES += \
    debug.stagefright.omx_default_rank=0

# Enable AAC 5.1 output
PRODUCT_PROPERTY_OVERRIDES += \
    media.aac_51_output_enabled=true

# Disable media transcoding
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.fuse.transcode_user_control=true \
    persist.sys.fuse.transcode_enabled=false

# Do not power down SIM card when modem is sent to Low Power Mode.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.apm_sim_not_pwdn=1

# LTE, CDMA, GSM/WCDMA
PRODUCT_PROPERTY_OVERRIDES += \
    ro.ril.force_eri_from_xml=true \
    ro.telephony.default_network=10 \
    telephony.lteOnCdmaDevice=1 \
    persist.radio.mode_pref_nv10=1

# update 1x signal strength after 2s
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.snapshot_enabled=1 \
    persist.radio.snapshot_timer=2

PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.use_cc_names=true

PRODUCT_PROPERTY_OVERRIDES += \
    persist.vendor.radio.enableadvancedscan=false \
    persist.vendor.radio.rat_on=combine

# If data_no_toggle is 1 then active and dormancy enable at all times.
# If data_no_toggle is 0 there are no reports if the screen is off.
# Leaving this property unset defaults to '0'
# Due to RIL changes, setting this to 1 now enables toggling of limited
# system indications and does not impact data state changes.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.data_no_toggle=1

PRODUCT_PROPERTY_OVERRIDES += \
    keyguard.no_require_sim=true

# Audio Configuration
PRODUCT_PROPERTY_OVERRIDES += \
    persist.audio.handset.mic.type=digital \
    persist.audio.dualmic.config=endfire \
    persist.audio.fluence.voicecall=true \
    persist.audio.fluence.voicecomm=true \
    persist.audio.fluence.voicerec=false \
    persist.audio.fluence.speaker=false

PRODUCT_PROPERTY_OVERRIDES += \
    ro.config.vc_call_vol_steps=7 \
    ro.config.media_vol_steps=25

# Setup custom emergency number list based on the MCC. This is needed by RIL
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.custom_ecc=1

# Request modem to send PLMN name always irrespective
# of display condition in EFSPN.
# RIL uses this property.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.always_send_plmn=true

PRODUCT_PROPERTY_OVERRIDES += \
    vendor.rild.libpath=/vendor/lib/libril-qc-qmi-1.so

# Allow tethering without provisioning app
PRODUCT_PROPERTY_OVERRIDES += \
    net.tethering.noprovisioning=true

# Camera configuration
PRODUCT_PROPERTY_OVERRIDES += \
    camera.disable_zsl_mode=1

# SurfaceFlinger
PRODUCT_PROPERTY_OVERRIDES += \
    ro.surface_flinger.enable_frame_rate_override=false \
    ro.surface_flinger.supports_background_blur=0 \
    ro.surface_flinger.use_context_priority=true \
    ro.surface_flinger.max_frame_buffer_acquired_buffers=3 \
    ro.surface_flinger.has_wide_color_display=false \
    ro.surface_flinger.running_without_sync_framework=false \
    ro.surface_flinger.has_HDR_display=false \
    ro.surface_flinger.present_time_offset_from_vsync_ns=0 \
    ro.surface_flinger.force_hwc_copy_for_virtual_displays=true \
    ro.surface_flinger.max_virtual_display_dimension=2048 \
    ro.surface_flinger.use_vr_flinger=false \
    ro.surface_flinger.start_graphics_allocator_service=true \
    ro.surface_flinger.primary_display_orientation=ORIENTATION_0 \
    ro.surface_flinger.clear_slots_with_set_layer_buffer=true

# msm_irqbalance
PRODUCT_PACKAGES += \
    msm_irqbalance

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/msm_irqbalance.conf:$(TARGET_COPY_OUT_VENDOR)/etc/msm_irqbalance.conf

# Input resampling configuration
PRODUCT_PROPERTY_OVERRIDES += \
    ro.input.noresample=1

# Reduce client buffer size for fast audio output tracks
PRODUCT_PROPERTY_OVERRIDES += \
    af.fast_track_multiplier=1

PRODUCT_PROPERTY_OVERRIDES += \
    dalvik.vm.dex2oat64.enabled=false \
    dalvik.vm.dex2oat-swap=false \
    dalvik.vm.image-dex2oat-threads=4 \
    dalvik.vm.image-dex2oat-cpu-set=0,1,2,3 \
    dalvik.vm.dex2oat-threads=2 \
    dalvik.vm.dex2oat-cpu-set=2,3 \
    dalvik.vm.boot-dex2oat-threads=4 \
    dalvik.vm.boot-dex2oat-cpu-set=0,1,2,3 \
    ro.sys.fw.dex2oat_thread_count=4

# Inherit 512M Android Go defaults.
$(call inherit-product, build/make/target/product/go_defaults_512.mk)

# Setup dalvik vm configs
PRODUCT_PROPERTY_OVERRIDES += \
    dalvik.vm.heapstartsize=16m \
    dalvik.vm.heaptargetutilization=0.75 \
    dalvik.vm.heapminfree=2m \
    dalvik.vm.heapmaxfree=8m

# Dalvik heap
PRODUCT_PROPERTY_OVERRIDES += \
    dalvik.vm.foreground-heap-growth-multiplier=2.0

# Battery
PRODUCT_PROPERTY_OVERRIDES += \
    ro.config.small_battery=true

# Perf
PRODUCT_PROPERTY_OVERRIDES += \
    ro.qualcomm.perf.cores_online=4 \
    ro.vendor.extension_library=/vendor/lib/libqti-perfd-client.so

# Subsystem ramdump
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.ssr.enable_debug=0 \
    persist.sys.ssr.enable_ramdumps=0

# Charger
PRODUCT_PROPERTY_OVERRIDES += \
    ro.charger.enable_suspend=true

# Hardware
PRODUCT_PROPERTY_OVERRIDES += \
    ro.hardware.egl=adreno

# SoC
PRODUCT_PROPERTY_OVERRIDES += \
    ro.soc.manufacturer=Qualcomm \
    ro.soc.model=MSM8974

# XML format
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.binary_xml=false

# Device was launched with K
$(call inherit-product, $(SRC_TARGET_DIR)/product/product_launched_with_k.mk)

# Partitions
$(call inherit-product, $(SRC_TARGET_DIR)/product/non_ab_device.mk)

# Broadcom BT driver
$(call inherit-product-if-exists, $(LOCAL_PATH)/bluetooth/bcm.mk)

# Broadcom WIFI driver
$(call inherit-product-if-exists, $(LOCAL_PATH)/wlan/bcm.mk)

# Vendor security patch level
PRODUCT_PROPERTY_OVERRIDES += \
    ro.lineage.build.vendor_security_patch=2016-10-05

# Updater properties
PRODUCT_PROPERTY_OVERRIDES += \
    persist.vendor.recovery_update=false

# Disable multiuser feature
PRODUCT_PROPERTY_OVERRIDES += \
    fw.max_users=1

# Increase watchdog timeout multiplier to workaround ANRs
PRODUCT_PROPERTY_OVERRIDES += \
    ro.hw_timeout_multiplier=6

# Since ($SRC_TARGET)/product/generic.mk is included instead of full_base.mk the device config also need to
#  pick up the default Android Platform product locale list
$(call inherit-product, $(SRC_TARGET_DIR)/product/languages_default.mk)

# Cgroup and task_profiles for bfqio
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/cgroups.json:$(TARGET_COPY_OUT_VENDOR)/etc/cgroups.json \
    $(LOCAL_PATH)/task_profiles.json:$(TARGET_COPY_OUT_VENDOR)/etc/task_profiles.json
