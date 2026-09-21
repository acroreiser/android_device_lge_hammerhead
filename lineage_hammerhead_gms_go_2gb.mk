# Boot animation
TARGET_SCREEN_HEIGHT := 1920
TARGET_SCREEN_WIDTH := 1080

# Inherit some common LineageOS stuff.
$(call inherit-product, vendor/lineage/config/common_mini_go_phone.mk)

# Inherit device configuration
$(call inherit-product, device/lge/hammerhead/full_hammerhead.mk)

## Device identifier. This must come after all inclusions
PRODUCT_DEVICE := hammerhead
PRODUCT_NAME := lineage_hammerhead_gms_go_2gb
PRODUCT_BRAND := google
PRODUCT_MODEL := Nexus 5
PRODUCT_MANUFACTURER := LGE

PRODUCT_BUILD_PROP_OVERRIDES += \
    DeviceName=hammerhead \
    BuildDesc="hammerhead-user 6.0.1 M4B30Z 3437181 release-keys" \
    BuildFingerprint=google/hammerhead/hammerhead:6.0.1/M4B30Z/3437181:user/release-keys

# GMS GO (2GB)
WITH_GMS := true
GMS_MAKEFILE := gms_go_2gb.mk

$(call inherit-product, vendor/lineage/config/partner_gms.mk)

# DocumentsUI overlay for Go
PRODUCT_PACKAGES += \
    DocumentsUIOverlayGo

# Overlay for Gboard
PRODUCT_PACKAGES += \
    GboardOverlay

# Overlay for Google Messages
PRODUCT_PACKAGES += \
    MessagesGoOverlay

# Trebuchet overlay
PRODUCT_PACKAGES += \
    TrebuchetGoOverlay
