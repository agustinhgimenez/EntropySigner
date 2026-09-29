#include "system/device_info.h"

#include <Arduino.h>

#include "security/secure_log.h"

namespace es {
namespace system {

void logDeviceInfo() {
    ES_LOG_INFO("Chip: %s rev %d, %d cores @ %lu MHz", ESP.getChipModel(), ESP.getChipRevision(),
                ESP.getChipCores(), static_cast<unsigned long>(ESP.getCpuFreqMHz()));
    ES_LOG_INFO("Flash: %lu KB", static_cast<unsigned long>(ESP.getFlashChipSize() / 1024));
    ES_LOG_INFO("PSRAM: %lu KB", static_cast<unsigned long>(ESP.getPsramSize() / 1024));
    ES_LOG_DEBUG("Free heap: %lu bytes", static_cast<unsigned long>(ESP.getFreeHeap()));
    ES_LOG_DEBUG("SDK: %s", ESP.getSdkVersion());
}

}  // namespace system
}  // namespace es
