// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Trunk Recorder P25 Stream Plugin
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 Bryan Biedenkapp, N2PLL
 *
 */
#include "../../trunk-recorder/plugin_manager/plugin_api.h"

#include <boost/asio.hpp>
#include <boost/dll/alias.hpp>

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using boost::asio::ip::udp;

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

const uint8_t DVM_RTP_PAYLOAD_TYPE = 0x56U;

#define RTP_HEADER_LENGTH_BYTES 12
#define RTP_EXTENSION_HEADER_LENGTH_BYTES 4
#define RTP_FNE_HEADER_LENGTH_BYTES 16
#define RTP_FNE_HEADER_LENGTH_EXT_LEN 4
#define RTP_FIXED_OVERHEAD (RTP_HEADER_LENGTH_BYTES + RTP_EXTENSION_HEADER_LENGTH_BYTES + RTP_FNE_HEADER_LENGTH_BYTES)

#define RTP_END_OF_CALL_SEQ 65535

#define FNE_PING_INTERVAL_MS 5000

const uint8_t DVM_FRAME_START = 0xFEU;

/**
 * @brief Network Functions
 */
namespace NET_FUNC {
    enum ENUM : uint8_t {
        ILLEGAL = 0xFFU,                        //!< Illegal Function

        PROTOCOL = 0x00U,                       //!< Digital Protocol Function

        RPTL = 0x60U,                           //!< Repeater Login
        RPTK = 0x61U,                           //!< Repeater Authorisation
        RPTC = 0x62U,                           //!< Repeater Configuration

        RPT_DISC = 0x70U,                       //!< Repeater Disconnect

        PING = 0x74U,                           //!< Ping
        PONG = 0x75U,                           //!< Pong

        ACK = 0x7EU,                            //!< Packet Acknowledge
        NAK = 0x7FU,                            //!< Packet Negative Acknowledge
    };
};

#define NET_CTRL_SWITCH_OVER 0x20U

/**
 * @brief Network Sub-Functions
 */
namespace NET_SUBFUNC {
    enum ENUM : uint8_t {
        NOP = 0xFFU,                            //!< No Operation Sub-Function

        PROTOCOL_SUBFUNC_P25 = 0x01U,           //!< P25
    };
};

#define TAG_P25_DATA            "P25D"

#define TAG_REPEATER_LOGIN      "RPTL"
#define TAG_REPEATER_AUTH       "RPTK"
#define TAG_REPEATER_CONFIG     "RPTC"

const uint32_t  PACKET_PAD = 8U;
const uint32_t  MSG_HDR_SIZE = 24U;
const uint32_t  P25_LDU1_PACKET_LENGTH = 193U;  // 24 byte header + DFSI data + 1 byte frame type + 12 byte enc sync
const uint32_t  P25_LDU2_PACKET_LENGTH = 181U;  // 24 byte header + DFSI data + 1 byte frame type

// TIA-102.BAAC-D Section 2.11
/** @brief Data Unit ID(s) */
namespace DUID {
    /** @brief Data Unit ID(s) */
    enum E : uint8_t {
        TDU = 0x03U,                            //!< Simple Terminator Data Unit
        LDU1 = 0x05U,                           //!< Logical Link Data Unit 1
        LDU2 = 0x0AU,                           //!< Logical Link Data Unit 2
    };
}

/** @brief DVM Network Frame Types */
namespace FrameType {
    /** @brief DVM Network Frame Types */
    enum E : uint8_t {
        TERMINATOR = 0x03U,                     //!< TDU/TDULC Terminator
        DATA_UNIT = 0x00U                       //!< Standard Data Unit
    };
}

/** @name Manufacturer IDs */
/** @brief Standard MFId */
const uint8_t   MFG_STANDARD = 0x00U;

/** @name Encryption Algorithms */
/** @brief Unencrypted */
const uint8_t   ALGO_UNENCRYPT = 0x80U;

const uint8_t   P25_LCO_GROUP = 0x00U;          //!< GRP VCH USER - Group Voice Channel User

const uint32_t  MI_LENGTH_BYTES = 9U;
const uint32_t  RAW_IMBE_LENGTH_BYTES = 11U;

/** @brief DFSI Frame Type */
namespace DFSIFrameType {
    /** @brief DFSI Frame Type */
    enum E : uint8_t {
        LDU1_VOICE1 = 0x62U,                //!< IMBE LDU1 - Voice 1
        LDU1_VOICE2 = 0x63U,                //!< IMBE LDU1 - Voice 2
        LDU1_VOICE3 = 0x64U,                //!< IMBE LDU1 - Voice 3 + Link Control
        LDU1_VOICE4 = 0x65U,                //!< IMBE LDU1 - Voice 4 + Link Control
        LDU1_VOICE5 = 0x66U,                //!< IMBE LDU1 - Voice 5 + Link Control
        LDU1_VOICE6 = 0x67U,                //!< IMBE LDU1 - Voice 6 + Link Control
        LDU1_VOICE7 = 0x68U,                //!< IMBE LDU1 - Voice 7 + Link Control
        LDU1_VOICE8 = 0x69U,                //!< IMBE LDU1 - Voice 8 + Link Control
        LDU1_VOICE9 = 0x6AU,                //!< IMBE LDU1 - Voice 9 + Low Speed Data

        LDU2_VOICE10 = 0x6BU,               //!< IMBE LDU2 - Voice 10
        LDU2_VOICE11 = 0x6CU,               //!< IMBE LDU2 - Voice 11
        LDU2_VOICE12 = 0x6DU,               //!< IMBE LDU2 - Voice 12 + Encryption Sync
        LDU2_VOICE13 = 0x6EU,               //!< IMBE LDU2 - Voice 13 + Encryption Sync
        LDU2_VOICE14 = 0x6FU,               //!< IMBE LDU2 - Voice 14 + Encryption Sync
        LDU2_VOICE15 = 0x70U,               //!< IMBE LDU2 - Voice 15 + Encryption Sync
        LDU2_VOICE16 = 0x71U,               //!< IMBE LDU2 - Voice 16 + Encryption Sync
        LDU2_VOICE17 = 0x72U,               //!< IMBE LDU2 - Voice 17 + Encryption Sync
        LDU2_VOICE18 = 0x73U,               //!< IMBE LDU2 - Voice 18 + Low Speed Data
    };
}

const uint32_t  DFSI_LDU1_VOICE1_FRAME_LENGTH_BYTES = 22U;
const uint32_t  DFSI_LDU1_VOICE2_FRAME_LENGTH_BYTES = 14U;
const uint32_t  DFSI_LDU1_VOICE3_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE4_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE5_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE6_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE7_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE8_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU1_VOICE9_FRAME_LENGTH_BYTES = 16U;

const uint32_t  DFSI_LDU2_VOICE10_FRAME_LENGTH_BYTES = 22U;
const uint32_t  DFSI_LDU2_VOICE11_FRAME_LENGTH_BYTES = 14U;
const uint32_t  DFSI_LDU2_VOICE12_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE13_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE14_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE15_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE16_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE17_FRAME_LENGTH_BYTES = 17U;
const uint32_t  DFSI_LDU2_VOICE18_FRAME_LENGTH_BYTES = 16U;

const uint8_t   NULL_IMBE[] = { 0x04U, 0x0CU, 0xFDU, 0x7BU, 0xFBU, 0x7DU, 0xF2U, 0x7BU, 0x3DU, 0x9EU, 0x45U };
const uint8_t   ENCRYPTED_NULL_IMBE[] = { 0xFCU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U };

/**
 * @brief Network Peer Connection Status
 */
enum NET_CONN_STATUS {
    // Common States
    NET_STAT_WAITING_CONNECT,                   //!< Waiting for Connection
    NET_STAT_WAITING_LOGIN,                     //!< Waiting for Login
    NET_STAT_WAITING_AUTHORISATION,             //!< Waiting for Authorization
    NET_STAT_WAITING_CONFIG,                    //!< Waiting for Configuration
    NET_STAT_RUNNING,                           //!< Peer Running

    NET_STAT_INVALID = 0x7FFFFFF                //!< Invalid
};

// ---------------------------------------------------------------------------
//  Macros
// ---------------------------------------------------------------------------

/**
 * @brief Sets a uint32_t into 4 bytes of a buffer/array. (32-bit value).
 * @ingroup common
 * @param val uint32_t value to set
 * @param buffer uint8_t buffer to set value on
 * @param offset Offset within uint8_t buffer
 */
#define SET_UINT32(val, buffer, offset)                 \
            buffer[0U + offset] = (val >> 24) & 0xFFU;  \
            buffer[1U + offset] = (val >> 16) & 0xFFU;  \
            buffer[2U + offset] = (val >> 8) & 0xFFU;   \
            buffer[3U + offset] = (val >> 0) & 0xFFU;

/**
 * @brief Gets a uint32_t consisting of 4 bytes from a buffer/array. (32-bit value).
 * @ingroup common
 * @param buffer uint8_t buffer to get value from
 * @param offset Offset within uint8_t buffer
 */
#define GET_UINT32(buffer, offset)                      \
            (buffer[offset + 0U] << 24)     |           \
            (buffer[offset + 1U] << 16)     |           \
            (buffer[offset + 2U] << 8)      |           \
            (buffer[offset + 3U] << 0);
/**
 * @brief Sets a uint32_t into 3 bytes of a buffer/array. (24-bit value).
 * @ingroup common
 * @param val uint32_t value to set
 * @param buffer uint8_t buffer to set value on
 * @param offset Offset within uint8_t buffer
 */
#define SET_UINT24(val, buffer, offset)                 \
            buffer[0U + offset] = (val >> 16) & 0xFFU;  \
            buffer[1U + offset] = (val >> 8) & 0xFFU;   \
            buffer[2U + offset] = (val >> 0) & 0xFFU;

/**
 * @brief Gets a uint32_t consisting of 3 bytes from a buffer/array. (24-bit value).
 * @ingroup common
 * @param buffer uint8_t buffer to get value from
 * @param offset Offset within uint8_t buffer
 */
#define GET_UINT24(buffer, offset)                      \
            (buffer[offset + 0U] << 16)     |           \
            (buffer[offset + 1U] << 8)      |           \
            (buffer[offset + 2U] << 0);

/**
 * @brief Sets a uint16_t into 2 bytes of a buffer/array. (16-bit value).
 * @ingroup common
 * @param val uint16_t value to set
 * @param buffer uint8_t buffer to set value on
 * @param offset Offset within uint8_t buffer
 */
#define SET_UINT16(val, buffer, offset)                 \
            buffer[0U + offset] = (val >> 8) & 0xFFU;   \
            buffer[1U + offset] = (val >> 0) & 0xFFU;
/**
 * @brief Gets a uint16_t consisting of 2 bytes from a buffer/array. (16-bit value).
 * @ingroup common
 * @param buffer uint8_t buffer to get value from
 * @param offset Offset within uint8_t buffer
 */
#define GET_UINT16(buffer, offset)                      \
            ((buffer[offset + 0U] << 8) & 0xFF00U)  |   \
            ((buffer[offset + 1U] << 0) & 0x00FFU);

// ---------------------------------------------------------------------------
//  Global Functions
// ---------------------------------------------------------------------------

/**
 * @brief Calculates the CRC-16-CCITT (0x1021) checksum for a given data buffer.
 * @param data Pointer to the data buffer.
 * @param len Length of the data in bits.
 * @returns uint16_t The calculated CRC-16-CCITT checksum. 
 */
uint16_t CRC16_CCITT(const uint8_t *data, size_t len) 
{
    uint16_t crc = 0xFFFFU;
    for (size_t i = 0; i < len; i++) {
        const uint8_t byte = data[i / 8U];
        const uint8_t bitPos = (uint8_t)(7U - (i % 8U));

        const bool bit1 = ((byte >> bitPos) & 0x01U) != 0U;
        const bool bit2 = (crc & 0x8000U) != 0U;

        crc = (uint16_t)(crc << 1);
        if (bit1 ^ bit2) {
            crc ^= 0x1021U;
        }
    }

    return (uint16_t)(crc & 0xFFFFU);
}

/**
 * @brief Generates a unique call key based on the short name and call number.
 * @param short_name System short name.
 * @param call_num Trunk-recorder call number.
 * @returns std::string Stable key in the format "short_name:call_num".
 */
std::string make_call_key(const std::string& short_name, long call_num)
{
    std::ostringstream oss;
    oss << short_name << ":" << call_num;
    return oss.str();
}

/**
 * @brief Generates a TGID fallback key for cross-callback correlation.
 * @param short_name System short name.
 * @param source_tgid Source talkgroup ID from trunk-recorder.
 * @param dst_tgid Destination talkgroup ID after route translation.
 * @returns std::string Fallback key in the format "short_name:source_tgid:dst_tgid".
 */
std::string make_tgid_call_key(const std::string& short_name, long source_tgid, uint32_t dst_tgid)
{
    std::ostringstream oss;
    const long normalized_source_tgid = (source_tgid < 0) ? 0 : source_tgid;
    const uint32_t normalized_dst_tgid = dst_tgid & 0x00FFFFFFU;
    oss << short_name << ":" << normalized_source_tgid << ":" << normalized_dst_tgid;
    return oss.str();
}

/**
 * @brief Generates a mux lane key for one destination stream lane.
 * @param route_key Route signature key.
 * @param short_name Source short name.
 * @param dst_tgid Destination TGID.
 * @returns std::string A unique mux lane key.
 */
std::string make_mux_lane_key(const std::string& route_key, const std::string &short_name, uint32_t dst_tgid)
{
    std::ostringstream oss;
    oss << short_name << ":" << dst_tgid;
    oss << ":" << route_key;
    return oss.str();
}

// ---------------------------------------------------------------------------
//  Structure Declaration
// ---------------------------------------------------------------------------

/**
 * @brief Represents a routing entry for a talkgroup.
 */

struct Route {
    long tgid = 0;
    long dstTgid = 0;
    std::string short_name;
};

std::string make_route_lane_key(const Route* route)
{
    if (route == nullptr) {
        return "wildcard";
    }

    std::ostringstream oss;
    oss << route->tgid << ":" << route->dstTgid << ":" << route->short_name;
    return oss.str();
}

/**
 * @brief Represents the configuration for the FNE connection.
 */

struct FneConfig {
    std::string address;
    uint16_t port = 62031;
    uint32_t peerId = 0;
    std::string password;

    std::string identity = "trunk-recorder";
    std::string software = "TRUNKREC_DVM";

    uint32_t retryInterval = 3000;
    uint32_t maxMissedPings = 10;
    uint32_t pacedCallTimeoutMs = 10000;
    uint32_t orphanCallTimeoutMs = 12000;
    uint32_t endedCallCleanupMs = 30000;
    uint32_t sendWorkers = 4;
};


/**
 * @brief Represents the header of a P25 FNE message.
 */

struct P25MessageHdr {
    uint8_t lco = P25_LCO_GROUP;

    uint32_t srcId = 0U;
    uint32_t dstId = 0U;

    uint16_t sysId = 0U;

    uint8_t controlByte = 0x00U;

    uint8_t mfid = MFG_STANDARD;

    uint32_t netId = 0U;

    uint8_t lsd1 = 0U;
    uint8_t lsd2 = 0U;

    uint8_t serviceOptions = 0U;

    uint8_t algId = ALGO_UNENCRYPT;
    uint16_t kId = 0U;

    std::array<uint8_t, MI_LENGTH_BYTES> mi{};
};

/**
 * @brief Represents the state of a P25 call.
 */

struct P25CallState {
    std::array<std::array<uint8_t, RAW_IMBE_LENGTH_BYTES>, 9U> imbe{};
    uint8_t imbeCount = 0U;

    bool nextIsLDU2 = false;
    bool leading_silence_sent = false;

    P25MessageHdr header;
};

/**
 * @brief Represents the state of an outbound frame.
 */

struct OutboundFrame {
    std::string call_key;
    std::string lane_key;
    uint32_t dst_tgid = 0U;
    std::vector<uint8_t> payload;
    bool end_of_call = false;
};

/**
 * @brief Represents a compact summary of an outbound frame for diagnostics.
 */

struct FrameLogInfo {
    std::string call_key;
    std::string lane_key;
    uint32_t dst_tgid = 0U;
    uint32_t src_id = 0U;
    uint32_t hdr_dst_id = 0U;
    uint8_t duid = 0U;
    uint8_t frame_len = 0U;
    size_t payload_size = 0U;
    bool end_of_call = false;
    bool valid_p25 = false;
};

/**
 * @brief Represents low-noise diagnostics for a single outbound call.
 */

struct CallDiagnosticState {
    bool first_queue_logged = false;
    bool first_dispatch_logged = false;
    bool first_send_logged = false;
    bool tdu_queue_logged = false;
    bool tdu_dispatch_logged = false;
    bool tdu_send_logged = false;
    bool first_drop_logged = false;
    uint64_t queued_frames = 0U;
    uint64_t dispatched_frames = 0U;
    uint64_t send_attempts = 0U;
    uint64_t dropped_frames = 0U;
};

/**
 * @brief Represents the state of a stream.
 */

struct StreamState {
    uint32_t streamId = 0;
    uint32_t timestamp = 0;

    bool timestampInit = false;
    std::chrono::steady_clock::time_point next_protocol_send_at{};
};

/**
 * @brief Represents the state of a mux lane.
 */

struct MuxLaneState {
    std::string active_call_key;
    std::deque<std::string> waiting_calls;
};

/**
 * @brief Represents the state of a call mux lane.
 */

struct CallMuxState {
    std::string lane_key;
    std::string tgid_call_key;
    bool active = false;
    bool queued = false;
    bool ended = false;
    bool synthetic_end_queued = false;
    bool buffered_log_sent = false;
    bool header_valid = false;
    bool encrypted = false;
    bool next_is_ldu2 = false;
    uint64_t buffered_frames = 0U;
    long source_tgid = 0;
    P25MessageHdr header;
    std::chrono::steady_clock::time_point last_activity{};
};

// ---------------------------------------------------------------------------
//  Class Declaration
// ---------------------------------------------------------------------------

/**
 * @brief Implements the actual DVM trunk-recorder FNE P25 stream plugin.
 */
class DVMTRP25Stream final : public Plugin_Api {
public:
    /**
     * @brief Initializes a new instance of the DVMTRP25Stream class
     */
    DVMTRP25Stream() : socket(io) { }

    /**
     * @brief Parses the plugin configuration data.
     * @param config_data JSON configuration data.
     * @returns int 0 on success, non-zero on failure.
     */
    int parse_config(json config_data) override {
        if (!config_data.contains("fne") || !config_data["fne"].is_object()) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: missing required fne config object";
            return -1;
        }

        json fne = config_data["fne"];
        fne_config.address = fne.value("address", "");
        fne_config.port = static_cast<uint16_t>(fne.value("port", 62031));
        fne_config.peerId = (uint32_t)(fne.value("peerId", 0));
        fne_config.password = fne.value("password", "");

        fne_config.identity = fne.value("identity", fne_config.identity);
        fne_config.retryInterval = (uint32_t)(fne.value("retryIntervalMs", fne_config.retryInterval));
        fne_config.maxMissedPings = (uint32_t)(fne.value("maxMissedPings", fne_config.maxMissedPings));
        fne_config.pacedCallTimeoutMs = (uint32_t)(fne.value("pacedCallTimeoutMs", fne_config.pacedCallTimeoutMs));
        fne_config.orphanCallTimeoutMs = (uint32_t)(fne.value("orphanCallTimeoutMs", fne_config.orphanCallTimeoutMs));
        fne_config.endedCallCleanupMs = (uint32_t)(fne.value("endedCallCleanupMs", fne_config.endedCallCleanupMs));
        fne_config.sendWorkers = (uint32_t)(fne.value("sendWorkers", fne_config.sendWorkers));
        if (fne_config.maxMissedPings == 0U) {
            fne_config.maxMissedPings = 10U;
        }
        if (fne_config.pacedCallTimeoutMs == 0U) {
            fne_config.pacedCallTimeoutMs = 10000U;
        }
        if (fne_config.orphanCallTimeoutMs < 1000U) {
            fne_config.orphanCallTimeoutMs = 1000U;
        }
        if (fne_config.endedCallCleanupMs < 5000U) {
            fne_config.endedCallCleanupMs = 5000U;
        }
        if (fne_config.sendWorkers == 0U) {
            fne_config.sendWorkers = 1U;
        }
        if (fne_config.sendWorkers > 32U) {
            fne_config.sendWorkers = 32U;
        }

        max_queue_depth = static_cast<size_t>(config_data.value("maxQueueDepth", 8192));

        routes.clear();
        if (config_data.contains("routes") && config_data["routes"].is_array()) {
            for (const auto &entry : config_data["routes"]) {
                Route route;
                route.tgid = static_cast<long>(entry.value("TGID", 0));
                route.dstTgid = static_cast<long>(entry.value("dstTgid", 0));
                route.short_name = entry.value("shortName", "");
                routes.push_back(route);
            }
        }

        if (routes.empty()) {
            Route wildcard;
            wildcard.tgid = 0;
            routes.push_back(wildcard);
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: no routes configured, enabling wildcard route";
        }

        if (fne_config.address.empty() || fne_config.peerId == 0 || fne_config.password.empty()) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: fne.address, fne.peerId, and fne.password are required";
            return -1;
        }

        BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: configured for FNE " << fne_config.address << ":" << fne_config.port
                                << ", peerId = " << fne_config.peerId
                                << ", routes = " << routes.size()
                                << ", maxMissedPings = " << fne_config.maxMissedPings
                                << ", pacedCallTimeoutMs = " << fne_config.pacedCallTimeoutMs
                                << ", orphanCallTimeoutMs = " << fne_config.orphanCallTimeoutMs
                                << ", endedCallCleanupMs = " << fne_config.endedCallCleanupMs
                                << ", sendWorkers = " << fne_config.sendWorkers;

        return 0;
    }

    /**
     * @brief Starts the plugin.
     * @returns int 
     */
    int start() override {
        try {
            udp::resolver resolver(io);
            udp::resolver::results_type endpoints = resolver.resolve(udp::v4(), fne_config.address, std::to_string(fne_config.port));
            remote_endpoint = *endpoints.begin();

            socket.open(udp::v4());
            socket.non_blocking(true);

            running.store(true);
            start_sender_workers();
            set_net_state(NET_STAT_WAITING_CONNECT, "start");
            next_retry_at = std::chrono::steady_clock::now();
            worker = std::thread(&DVMTRP25Stream::worker_loop, this);

            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: started";
            return 0;
        } catch (const std::exception &ex) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: start failed: " << ex.what();
            return -1;
        }
    }

    /**
     * @brief Stops the plugin.
     * @returns int 
     */
    int stop() override {
        running.store(false);
        if (worker.joinable()) {
            worker.join();
        }

        stop_sender_workers();

        if (socket.is_open()) {
            send_disconnect();
            boost::system::error_code ec;
            socket.close(ec);
        }

        BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: stopped";
        return 0;
    }

    /**
     * @brief Factory method to create a new instance of the DVMTRStream plugin.
     * @returns boost::shared_ptr<DVMTRStream>
     */
    static boost::shared_ptr<DVMTRP25Stream> create() {
        return boost::shared_ptr<DVMTRP25Stream>(new DVMTRP25Stream());
    }

    /**
     * @brief Handles the end of a call.
     * @param call_info Call data structure containing information about the call.
     * @returns int 0 on success, non-zero on failure.
     */
    int call_end(Call_Data_t call_info) override {
        const Route *route = find_route(call_info.talkgroup, call_info.short_name, call_info.encrypted);
        uint32_t dst_tgid = resolve_dst_tgid(route, call_info.talkgroup);
        std::string call_key = make_call_key(call_info.short_name, call_info.call_num);
        const std::string tgid_call_key = make_tgid_call_key(call_info.short_name, call_info.talkgroup, dst_tgid);

        P25CallState state;
        bool have_state = false;

        const auto load_p25_state = [&]() {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            auto it = p25_call_state.find(call_key);
            if (it != p25_call_state.end()) {
                state = it->second;
                p25_call_state.erase(it);
                have_state = true;
            }
        };

        load_p25_state();

        const std::string fallback_lane_key = make_mux_lane_key(make_route_lane_key(route), call_info.short_name, dst_tgid);
        bool have_mux_state = has_mux_call_state(call_key);
        if (!have_state && !have_mux_state && call_info.call_num <= 0) {
            const std::string tracked_call_key = resolve_tracked_call_key_for_tgid(tgid_call_key);
            if (!tracked_call_key.empty() && tracked_call_key != call_key) {
                const std::string original_call_key = call_key;
                call_key = tracked_call_key;
                call_end_fallback_matches++;
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: call_end matched tracked TGID fallback"
                                           << ", callKey = " << tracked_call_key
                                           << ", originalCallKey = " << original_call_key
                                           << ", tgidKey = " << tgid_call_key
                                           << ", callNum = " << call_info.call_num
                                           << ", fallbackMatches = " << call_end_fallback_matches;
                load_p25_state();
                have_mux_state = has_mux_call_state(call_key);
            }
        }

        const std::string lane_key = resolve_lane_key_for_call(call_key, fallback_lane_key);

        // Guard against false call_end callbacks (for non-P25 or otherwise
        // unrouted calls): do not synthesize end frames unless this call had
        // real voice/mux state in this plugin.
        if (!have_state && !have_mux_state) {
            if (route != nullptr) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: call_end route matched but no voice/mux state, skipping fallback end injection"
                                           << ", callKey = " << call_key
                                           << ", callNum = " << call_info.call_num
                                           << ", tgid = " << call_info.talkgroup
                                           << ", sourceId = " << call_info.source_num
                                           << ", sysId = " << call_info.sys_num
                                           << ", shortName = " << call_info.short_name;
                return 0;
            } else {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: call_end no route/state, callKey = " << call_key
                                           << ", callNum = " << call_info.call_num
                                           << ", tgid = " << call_info.talkgroup
                                           << ", sysId = " << call_info.sys_num
                                           << ", shortName = " << call_info.short_name;
                return 0;
            }
        }

        const uint8_t partial_imbe_count = have_state ? state.imbeCount : 0U;
        if (have_state && state.imbeCount > 0U) {
            const uint8_t *null_frame = call_info.encrypted ? ENCRYPTED_NULL_IMBE : NULL_IMBE;
            while (state.imbeCount < 9U) {
                std::memcpy(state.imbe[state.imbeCount].data(), null_frame, RAW_IMBE_LENGTH_BYTES);
                state.imbeCount++;
            }

            OutboundFrame ldu_frame;
            ldu_frame.call_key = call_key;
            ldu_frame.end_of_call = false;
            ldu_frame.payload = build_ldu_payload(state, state.nextIsLDU2);
            schedule_mux_frame(lane_key, call_key, std::move(ldu_frame));
        }

        P25MessageHdr header;
        if (have_state) {
            header = state.header;
        } else {
            header.lco = P25_LCO_GROUP;
            header.srcId = (call_info.source_num > 0) ? ((uint32_t)(call_info.source_num) & 0x00FFFFFFU) : 0U;
            header.dstId = dst_tgid;
            header.sysId = static_cast<uint16_t>(call_info.sys_num & 0xFFFFU);
            header.serviceOptions = call_info.encrypted ? 0x40U : 0x00U;

            if (header.srcId == 0U) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: call_end using fallback header with missing source ID"
                                           << ", callKey = " << call_key
                                           << ", dstTg = " << header.dstId
                                           << ", sysId = " << header.sysId;
            }
        }

        queue_silence_ldu_pair(lane_key, call_key, header, call_info.encrypted, have_state ? state.nextIsLDU2 : false);

        OutboundFrame frame;
        frame.call_key = call_key;
        frame.payload = build_tdu_payload(header);
        frame.end_of_call = true;
        schedule_mux_frame(lane_key, call_key, std::move(frame));
        mark_mux_call_ended(call_key, lane_key);

        BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: call_end queued TDU"
                                << ", callKey = " << call_key
                                << ", callNum = " << call_info.call_num
                                << ", srcTg = " << call_info.talkgroup
                                << ", dstTg = " << header.dstId
                                << ", srcId = " << header.srcId
                                << ", haveVoiceState = " << have_state
                                << ", haveMuxState = " << have_mux_state
                                << ", partialImbe = " << (uint32_t)(partial_imbe_count)
                                << ", lane = " << lane_key;
        return 0;
    }

    /**
     * @brief Handles voice codec data for a call.
     * @param call Pointer to the Call object.
     * @param codec_type Type of the codec.
     * @param tgid Talkgroup ID.
     * @param src_id Source ID.
     * @param params Pointer to the codec parameters.
     * @param param_count Number of codec parameters.
     * @param errs Number of errors.
     * @returns int 0 on success, non-zero on failure.
     */
    int voice_codec_data(Call* call, int codec_type, long tgid, uint32_t src_id, const uint32_t* params, int param_count, int errs) override {
        if (!call || !params || param_count <= 0) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame (invalid callback args)";
            return 0;
        }

        if (codec_type != 0 || param_count < 8) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame, codecType = " << codec_type
                                     << ", paramCount = " << param_count;
            return 0;
        }

        System *system = call->get_system();
        if (!system) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame (missing system pointer)";
            return 0;
        }

        const long call_tgid = call->get_talkgroup();
        const long callback_tgid = tgid;
        const std::string short_name = call->get_short_name();
        const bool encrypted = call->get_encrypted();

        const Route* route = nullptr;
        long actual_tgid = 0;

        if (call_tgid > 0) {
            route = find_route(call_tgid, short_name, encrypted);
            if (route != nullptr) {
                actual_tgid = call_tgid;
            } else if (callback_tgid > 0 && callback_tgid != call_tgid) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: dropping callback TGID fallback due to mismatch"
                                         << ", callTg = " << call_tgid
                                         << ", cbTg = " << callback_tgid
                                         << ", shortName = " << short_name;
            }
        } else if (callback_tgid > 0) {
            route = find_route(callback_tgid, short_name, encrypted);
            if (route != nullptr) {
                actual_tgid = callback_tgid;
            }
        }

        if (!route) {
            return 0;
        } else {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: valid route for, tgid = " << actual_tgid
                                     << ", shortName = " << short_name
                                     << ", encrypted = " << encrypted;
        }

        const uint32_t dst_tgid = resolve_dst_tgid(route, actual_tgid);
        const std::string lane_key = make_mux_lane_key(make_route_lane_key(route), short_name, dst_tgid);

        const long current_src = call->get_current_source_id();
        uint32_t effective_src = 0U;
        if (current_src > 0 && current_src <= 0x00FFFFFFL) {
            effective_src = (uint32_t)(current_src);
        } else if (src_id > 0 && src_id <= 0x00FFFFFFU) {
            effective_src = src_id;
        }

        if (effective_src == 0U) {
            const std::string invalid_call_key = make_call_key(short_name, call->get_call_num());
            if (note_invalid_source_drop(invalid_call_key)) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: dropping voice frame with invalid source ID"
                                           << ", callKey = " << invalid_call_key
                                           << ", callNum = " << call->get_call_num()
                                           << ", callSrc = " << current_src
                                           << ", cbSrc = " << src_id
                                           << ", callTg = " << call_tgid
                                           << ", cbTg = " << callback_tgid
                                           << ", shortName = " << short_name;
            } else {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: dropping voice frame with invalid source ID"
                                         << ", callKey = " << invalid_call_key
                                         << ", callSrc = " << current_src
                                         << ", cbSrc = " << src_id
                                         << ", callTg = " << call_tgid
                                         << ", cbTg = " << callback_tgid;
            }
           return 0;
        }

        std::array<uint8_t, RAW_IMBE_LENGTH_BYTES> imbe{};
        if (!pack_imbe(params, param_count, imbe)) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: failed IMBE pack for tgid=" << actual_tgid;
            return 0;
        }

        const int sys_num = static_cast<int>(system->get_sys_id() & 0xFFFFU);
        const std::string call_key = make_call_key(short_name, call->get_call_num());
        const std::string tgid_call_key = make_tgid_call_key(short_name, actual_tgid, dst_tgid);

        P25CallState ready_state;
        bool emit_ldu = false;
        bool emit_ldu2 = false;
        bool queue_leading_silence = false;
        P25MessageHdr leading_header;
        P25MessageHdr current_header;
        bool current_next_is_ldu2 = false;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            P25CallState& state = p25_call_state[call_key];
            state.header = build_message_header(call, system, effective_src, actual_tgid, route);

            const uint32_t normalized_src = effective_src & 0x00FFFFFFU;
            const uint32_t normalized_dst = dst_tgid & 0x00FFFFFFU;
            if (state.header.srcId != normalized_src || state.header.dstId != normalized_dst) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: header normalization"
                                         << ", callKey = " << call_key
                                         << ", builtSrc = " << state.header.srcId
                                         << ", builtDst = " << state.header.dstId
                                         << ", normalizedSrc = " << normalized_src
                                         << ", normalizedDst = " << normalized_dst;
            }

            // Keep IDs pinned to validated callback-local values for this frame.
            state.header.srcId = normalized_src;
            state.header.dstId = normalized_dst;
            current_header = state.header;
            current_next_is_ldu2 = state.nextIsLDU2;

              if (!state.leading_silence_sent && state.imbeCount == 0U) {
                  state.leading_silence_sent = true;
                  queue_leading_silence = true;
                  leading_header = state.header;
              }

            std::memcpy(state.imbe[state.imbeCount].data(), imbe.data(), RAW_IMBE_LENGTH_BYTES);
            state.imbeCount++;

            if (state.imbeCount >= 9U) {
                ready_state = state;
                emit_ldu = true;
                emit_ldu2 = state.nextIsLDU2;

                state.imbeCount = 0U;
                state.nextIsLDU2 = !state.nextIsLDU2;
            }
        }

        update_call_mux_state_from_voice(call_key, tgid_call_key, lane_key, actual_tgid, current_header, encrypted, current_next_is_ldu2);

        if (queue_leading_silence) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: call route"
                                    << ", callKey = " << call_key
                                    << ", callNum = " << call->get_call_num()
                                    << ", srcTg = " << actual_tgid
                                    << ", dstTg = " << dst_tgid
                                    << ", srcId = " << effective_src
                                    << ", callSrc = " << current_src
                                    << ", cbSrc = " << src_id
                                    << ", sysId = " << sys_num
                                    << ", shortName = " << short_name
                                    << ", lane = " << lane_key
                                    << ", errs = " << errs;

            update_call_mux_state_from_voice(call_key, tgid_call_key, lane_key, actual_tgid, leading_header, encrypted, false);
            queue_silence_ldu_pair(lane_key, call_key, leading_header, encrypted, false);
        }

        if (emit_ldu) {
            OutboundFrame frame;
            frame.call_key = call_key;
            frame.end_of_call = false;
            frame.payload = build_ldu_payload(ready_state, emit_ldu2);

            if (frame.payload.size() >= MSG_HDR_SIZE &&
                std::memcmp(frame.payload.data(), TAG_P25_DATA, 4U) == 0) {
                const uint32_t hdr_src = ((uint32_t)(frame.payload[5U]) << 16) |
                    ((uint32_t)(frame.payload[6U]) << 8) |
                    ((uint32_t)(frame.payload[7U]) << 0);
                const uint32_t hdr_dst = ((uint32_t)(frame.payload[8U]) << 16) |
                    ((uint32_t)(frame.payload[9U]) << 8) |
                    ((uint32_t)(frame.payload[10U]) << 0);

                const uint32_t expected_src = effective_src & 0x00FFFFFFU;
                const uint32_t expected_dst = dst_tgid & 0x00FFFFFFU;
                if (hdr_src != expected_src || hdr_dst != expected_dst) {
                    BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: built payload header mismatch"
                                             << ", callKey = " << call_key
                                             << ", expectedSrc = " << expected_src
                                             << ", expectedDst = " << expected_dst
                                             << ", hdrSrc = " << hdr_src
                                             << ", hdrDst = " << hdr_dst
                                             << ", duid = " << (uint32_t)(frame.payload[22U])
                                             << ", frameLen = " << (uint32_t)(frame.payload[23U]);
                }
            }

            schedule_mux_frame(lane_key, call_key, std::move(frame));

            update_call_mux_state_from_voice(call_key, tgid_call_key, lane_key, actual_tgid, ready_state.header, encrypted, emit_ldu2 ? false : true);

            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: queued " << (emit_ldu2 ? "LDU2" : "LDU1")
                                     << ", callKey = " << call_key
                                     << ", callNum = " << call->get_call_num()
                                     << ", srcTg = " << actual_tgid
                                     << ", dstTg = " << dst_tgid;
        }

        return 0;
    }

private:
    /**
     * @brief Converts a network state to a short diagnostic name.
     * @param state Network connection state.
     * @returns const char* Human-readable network state name.
     */
    static const char* net_state_name(NET_CONN_STATUS state) {
        switch (state) {
            case NET_STAT_WAITING_CONNECT:
                return "WAITING_CONNECT";
            case NET_STAT_WAITING_LOGIN:
                return "WAITING_LOGIN";
            case NET_STAT_WAITING_AUTHORISATION:
                return "WAITING_AUTHORISATION";
            case NET_STAT_WAITING_CONFIG:
                return "WAITING_CONFIG";
            case NET_STAT_RUNNING:
                return "RUNNING";
            default:
                return "INVALID";
        }
    }

    /**
     * @brief Converts a DUID value to a short diagnostic name.
     * @param duid DUID value.
     * @returns const char* Human-readable DUID name.
     */
    static const char* duid_name(uint8_t duid) {
        switch (duid) {
            case DUID::TDU:
                return "TDU";
            case DUID::LDU1:
                return "LDU1";
            case DUID::LDU2:
                return "LDU2";
            default:
                return "UNKNOWN";
        }
    }

    /**
     * @brief Builds compact diagnostic metadata from an outbound frame.
     * @param frame Outbound frame to inspect.
     * @returns FrameLogInfo Summary of the outbound frame.
     */
    FrameLogInfo make_frame_log_info(const OutboundFrame& frame) const {
        FrameLogInfo frame_info;
        frame_info.call_key = frame.call_key;
        frame_info.lane_key = frame.lane_key;
        frame_info.dst_tgid = frame.dst_tgid;
        frame_info.payload_size = frame.payload.size();
        frame_info.end_of_call = frame.end_of_call;

        if (frame.payload.size() >= MSG_HDR_SIZE &&
            std::memcmp(frame.payload.data(), TAG_P25_DATA, 4U) == 0) {
            frame_info.valid_p25 = true;
            frame_info.src_id = GET_UINT24(frame.payload.data(), 5U);
            frame_info.hdr_dst_id = GET_UINT24(frame.payload.data(), 8U);
            frame_info.duid = frame.payload[22U];
            frame_info.frame_len = frame.payload[23U];
        }

        return frame_info;
    }

    /**
     * @brief Records a frame entering the outbound queue.
     * @param frame_info Frame diagnostics.
     */
    void note_outbound_queued(const FrameLogInfo& frame_info) {
        if (frame_info.call_key.empty()) {
            return;
        }

        bool log_first_queue = false;
        bool log_tdu_queue = false;
        uint64_t queued_frames = 0U;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
            CallDiagnosticState& state = call_diagnostic_state[frame_info.call_key];
            state.queued_frames++;
            queued_frames = state.queued_frames;

            if (!state.first_queue_logged) {
                state.first_queue_logged = true;
                log_first_queue = true;
            }

            if (frame_info.end_of_call && !state.tdu_queue_logged) {
                state.tdu_queue_logged = true;
                log_tdu_queue = true;
            }
        }

        if (log_first_queue) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: outbound queue started"
                                    << ", callKey = " << frame_info.call_key
                                    << ", lane = " << frame_info.lane_key
                                    << ", srcId = " << frame_info.src_id
                                    << ", dstTg = " << frame_info.dst_tgid
                                    << ", hdrDst = " << frame_info.hdr_dst_id
                                    << ", duid = " << (uint32_t)(frame_info.duid)
                                    << ", duidName = " << duid_name(frame_info.duid)
                                    << ", frameLen = " << (uint32_t)(frame_info.frame_len)
                                    << ", payloadBytes = " << frame_info.payload_size;
        }

        if (log_tdu_queue) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: outbound TDU queued"
                                    << ", callKey = " << frame_info.call_key
                                    << ", lane = " << frame_info.lane_key
                                    << ", srcId = " << frame_info.src_id
                                    << ", dstTg = " << frame_info.dst_tgid
                                    << ", queuedFrames = " << queued_frames;
        }
    }

    /**
     * @brief Records a frame entering a sender worker queue.
     * @param frame_info Frame diagnostics.
     * @param worker_index Sender worker index.
     * @param worker_depth Sender worker queue depth after enqueue.
     */
    void note_sender_dispatched(const FrameLogInfo& frame_info, size_t worker_index, size_t worker_depth) {
        if (frame_info.call_key.empty()) {
            return;
        }

        bool log_first_dispatch = false;
        bool log_tdu_dispatch = false;
        uint64_t dispatched_frames = 0U;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
            CallDiagnosticState& state = call_diagnostic_state[frame_info.call_key];
            state.dispatched_frames++;
            dispatched_frames = state.dispatched_frames;

            if (!state.first_dispatch_logged) {
                state.first_dispatch_logged = true;
                log_first_dispatch = true;
            }

            if (frame_info.end_of_call && !state.tdu_dispatch_logged) {
                state.tdu_dispatch_logged = true;
                log_tdu_dispatch = true;
            }
        }

        if (log_first_dispatch) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: sender dispatch started"
                                    << ", callKey = " << frame_info.call_key
                                    << ", workerIndex = " << worker_index
                                    << ", workerDepth = " << worker_depth
                                    << ", srcId = " << frame_info.src_id
                                    << ", dstTg = " << frame_info.dst_tgid
                                    << ", duid = " << (uint32_t)(frame_info.duid)
                                    << ", duidName = " << duid_name(frame_info.duid);
        }

        if (log_tdu_dispatch) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: sender dispatch TDU"
                                    << ", callKey = " << frame_info.call_key
                                    << ", workerIndex = " << worker_index
                                    << ", workerDepth = " << worker_depth
                                    << ", dispatchedFrames = " << dispatched_frames
                                    << ", dstTg = " << frame_info.dst_tgid;
        }
    }

    /**
     * @brief Records a protocol send attempt.
     * @param frame_info Frame diagnostics.
     * @param stream_id FNE stream ID used for the packet.
     * @param seq RTP sequence number.
     * @param timestamp RTP timestamp.
     */
    void note_protocol_send_attempt(const FrameLogInfo& frame_info, uint32_t stream_id, uint16_t seq, uint32_t timestamp) {
        if (frame_info.call_key.empty()) {
            return;
        }

        bool log_first_send = false;
        bool log_tdu_send = false;
        uint64_t queued_frames = 0U;
        uint64_t dispatched_frames = 0U;
        uint64_t send_attempts = 0U;
        uint64_t dropped_frames = 0U;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
            CallDiagnosticState& state = call_diagnostic_state[frame_info.call_key];
            state.send_attempts++;
            queued_frames = state.queued_frames;
            dispatched_frames = state.dispatched_frames;
            send_attempts = state.send_attempts;
            dropped_frames = state.dropped_frames;

            if (!state.first_send_logged) {
                state.first_send_logged = true;
                log_first_send = true;
            }

            if (frame_info.end_of_call && !state.tdu_send_logged) {
                state.tdu_send_logged = true;
                log_tdu_send = true;
            }
        }

        if (log_first_send) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: protocol send started"
                                    << ", callKey = " << frame_info.call_key
                                    << ", streamId = " << stream_id
                                    << ", seq = " << seq
                                    << ", timestamp = " << timestamp
                                    << ", srcId = " << frame_info.src_id
                                    << ", dstTg = " << frame_info.dst_tgid
                                    << ", hdrDst = " << frame_info.hdr_dst_id
                                    << ", duid = " << (uint32_t)(frame_info.duid)
                                    << ", duidName = " << duid_name(frame_info.duid)
                                    << ", frameLen = " << (uint32_t)(frame_info.frame_len);
        }

        if (log_tdu_send) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: protocol TDU send attempted"
                                    << ", callKey = " << frame_info.call_key
                                    << ", streamId = " << stream_id
                                    << ", seq = " << seq
                                    << ", timestamp = " << timestamp
                                    << ", srcId = " << frame_info.src_id
                                    << ", dstTg = " << frame_info.dst_tgid
                                    << ", queuedFrames = " << queued_frames
                                    << ", dispatchedFrames = " << dispatched_frames
                                    << ", sendAttempts = " << send_attempts
                                    << ", droppedFrames = " << dropped_frames;
        }
    }

    /**
     * @brief Records a dropped frame without logging every repeated drop.
     * @param frame_info Frame diagnostics.
     * @param reason Drop reason.
     */
    void note_frame_dropped(const FrameLogInfo& frame_info, const char* reason) {
        if (frame_info.call_key.empty()) {
            return;
        }

        bool log_drop = false;
        uint64_t dropped_frames = 0U;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
            CallDiagnosticState& state = call_diagnostic_state[frame_info.call_key];
            state.dropped_frames++;
            dropped_frames = state.dropped_frames;

            if (!state.first_drop_logged || frame_info.end_of_call) {
                state.first_drop_logged = true;
                log_drop = true;
            }
        }

        if (log_drop) {
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: dropped outbound frame"
                                       << ", reason = " << reason
                                       << ", callKey = " << frame_info.call_key
                                       << ", lane = " << frame_info.lane_key
                                       << ", srcId = " << frame_info.src_id
                                       << ", dstTg = " << frame_info.dst_tgid
                                       << ", duid = " << (uint32_t)(frame_info.duid)
                                       << ", duidName = " << duid_name(frame_info.duid)
                                       << ", callDroppedFrames = " << dropped_frames;
        }
    }

    /**
     * @brief Determines if an invalid source drop should be logged at warning level.
     * @param call_key Per-call key.
     * @returns bool True when this is the first invalid source drop for the call.
     */
    bool note_invalid_source_drop(const std::string& call_key) {
        std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
        return invalid_source_drop_keys.insert(call_key).second;
    }

    /**
     * @brief Clears per-call diagnostic state after a completed TDU path.
     * @param call_key Per-call key.
     */
    void clear_call_diagnostics(const std::string& call_key) {
        if (call_key.empty()) {
            return;
        }

        std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
        call_diagnostic_state.erase(call_key);
        invalid_source_drop_keys.erase(call_key);
    }

    /**
     * @brief Generates a per-owner blocking key for destination TGID diagnostics.
     * @param dst_tgid Destination TGID.
     * @param owner_call_key Current owner call key.
     * @param waiting_call_key Waiting call key.
     * @returns std::string Blocking diagnostic key.
     */
    std::string make_dst_tgid_block_key(uint32_t dst_tgid, const std::string& owner_call_key, const std::string& waiting_call_key) const {
        std::ostringstream oss;
        oss << dst_tgid << ":" << owner_call_key << ":" << waiting_call_key;
        return oss.str();
    }

    /**
     * @brief Returns the number of frames currently waiting in the outbound queue.
     * @returns size_t Outbound queue size.
     */
    size_t queued_frame_count() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return queue_size;
    }

    /**
     * @brief Logs a network state transition with current queue pressure.
     * @param new_state New network state.
     * @param reason Transition reason.
     */
    void set_net_state(NET_CONN_STATUS new_state, const char* reason) {
        const NET_CONN_STATUS old_state = net_state;
        net_state = new_state;

        if (old_state != new_state) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: FNE state changed"
                                    << ", from = " << net_state_name(old_state)
                                    << ", to = " << net_state_name(new_state)
                                    << ", reason = " << reason
                                    << ", queuedFrames = " << queued_frame_count();
        }
    }

    /**
     * @brief Logs when outbound frames are waiting while the FNE session is not running.
     * @param now Current time point.
     */
    void log_queue_waiting_for_session(const std::chrono::steady_clock::time_point& now) {
        size_t queued_frames = 0U;
        size_t queued_lanes = 0U;
        size_t dst_owners = 0U;
        std::string front_lane;
        std::string front_call_key;
        uint32_t front_dst_tgid = 0U;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queued_frames = queue_size;
            queued_lanes = lane_queues.size();
            dst_owners = dst_tgid_active_calls.size();

            if (!lane_rr.empty()) {
                front_lane = lane_rr.front();
                auto it = lane_queues.find(front_lane);
                if (it != lane_queues.end() && !it->second.empty()) {
                    front_call_key = it->second.front().call_key;
                    front_dst_tgid = it->second.front().dst_tgid;
                }
            }
        }

        if (queued_frames == 0U) {
            return;
        }

        const bool state_changed = (last_queue_wait_state != net_state);
        const bool size_changed = (last_queue_wait_size != queued_frames);
        if (!state_changed && !size_changed && now < next_queue_wait_log_at) {
            return;
        }

        int64_t next_retry_ms = -1;
        if (next_retry_at.time_since_epoch().count() != 0) {
            next_retry_ms = std::chrono::duration_cast<std::chrono::milliseconds>(next_retry_at - now).count();
            if (next_retry_ms < 0) {
                next_retry_ms = 0;
            }
        }

        queue_wait_logs++;
        BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: outbound queue waiting for FNE session"
                                   << ", state = " << net_state_name(net_state)
                                   << ", queuedFrames = " << queued_frames
                                   << ", lanes = " << queued_lanes
                                   << ", dstOwners = " << dst_owners
                                   << ", frontLane = " << front_lane
                                   << ", frontCallKey = " << front_call_key
                                   << ", frontDstTg = " << front_dst_tgid
                                   << ", nextRetryMs = " << next_retry_ms
                                   << ", awaitingPong = " << awaiting_pong
                                   << ", missedPongs = " << missed_ping_count
                                   << ", waitLogs = " << queue_wait_logs;

        last_queue_wait_state = net_state;
        last_queue_wait_size = queued_frames;
        next_queue_wait_log_at = now + std::chrono::milliseconds(2000);
    }

    /**
     * @brief Logs when the FNE session is running but queued frames did not dispatch.
     * @param now Current time point.
     */
    void log_running_queue_stall(const std::chrono::steady_clock::time_point& now) {
        size_t queued_frames = 0U;
        size_t queued_lanes = 0U;
        size_t dst_owners = 0U;
        std::string front_lane;
        std::string front_call_key;
        uint32_t front_dst_tgid = 0U;
        bool front_end_of_call = false;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queued_frames = queue_size;
            queued_lanes = lane_queues.size();
            dst_owners = dst_tgid_active_calls.size();

            if (!lane_rr.empty()) {
                front_lane = lane_rr.front();
                auto it = lane_queues.find(front_lane);
                if (it != lane_queues.end() && !it->second.empty()) {
                    front_call_key = it->second.front().call_key;
                    front_dst_tgid = it->second.front().dst_tgid;
                    front_end_of_call = it->second.front().end_of_call;
                }
            }
        }

        if (queued_frames == 0U) {
            return;
        }

        if (!front_call_key.empty() && !front_end_of_call && !is_non_end_frame_ready(front_call_key, now)) {
            return;
        }

        if (now < next_running_queue_stall_log_at) {
            return;
        }

        running_queue_stall_logs++;
        BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: outbound queue did not dispatch while FNE session is running"
                                   << ", queuedFrames = " << queued_frames
                                   << ", lanes = " << queued_lanes
                                   << ", dstOwners = " << dst_owners
                                   << ", frontLane = " << front_lane
                                   << ", frontCallKey = " << front_call_key
                                   << ", frontDstTg = " << front_dst_tgid
                                   << ", frontEndOfCall = " << front_end_of_call
                                   << ", stallLogs = " << running_queue_stall_logs;

        next_running_queue_stall_log_at = now + std::chrono::milliseconds(2000);
    }

    /**
     * @brief Packs OP25 IMBE params (u0..u7) into an 11-byte packed codeword.
     * @param params Pointer to the IMBE parameters.
     * @param param_count Number of IMBE parameters.
     * @param out Reference to the output byte array.
     * @returns bool True if packing was successful, false otherwise.
     */
    bool pack_imbe(const uint32_t* params, int param_count, std::array<uint8_t, RAW_IMBE_LENGTH_BYTES> &out) const {
        if (!params || param_count < 8) {
            return false;
        }

        const uint32_t u0 = params[0] & 0x0FFFU;
        const uint32_t u1 = params[1] & 0x0FFFU;
        const uint32_t u2 = params[2] & 0x0FFFU;
        const uint32_t u3 = params[3] & 0x0FFFU;
        const uint32_t u4 = params[4] & 0x07FFU;
        const uint32_t u5 = params[5] & 0x07FFU;
        const uint32_t u6 = params[6] & 0x07FFU;
        const uint32_t u7 = params[7] & 0x00FFU;

        out[0] = (uint8_t)(u0 >> 4);
        out[1] = (uint8_t)(((u0 & 0x0FU) << 4) + (u1 >> 8));
        out[2] = (uint8_t)(u1 & 0xFFU);
        out[3] = (uint8_t)(u2 >> 4);
        out[4] = (uint8_t)(((u2 & 0x0FU) << 4) + (u3 >> 8));
        out[5] = (uint8_t)(u3 & 0xFFU);
        out[6] = (uint8_t)(u4 >> 3);
        out[7] = (uint8_t)(((u4 & 0x07U) << 5) + (u5 >> 6));
        out[8] = (uint8_t)(((u5 & 0x3FU) << 2) + (u6 >> 9));
        out[9] = (uint8_t)(u6 >> 1);
        out[10] = (uint8_t)(((u6 & 0x01U) << 7) + (u7 >> 1));

        return true;
    }

    /**
     * @brief Builds a full silence-only call state for one LDU emission.
     * @param header Message header to apply.
     * @param encrypted Whether encrypted silence pattern should be used.
     * @returns P25CallState Pre-filled silence state.
     */
    P25CallState build_silence_state(const P25MessageHdr& header, bool encrypted) const {
        P25CallState state;
        state.header = header;
        state.imbeCount = 9U;
        const uint8_t* null_frame = encrypted ? ENCRYPTED_NULL_IMBE : NULL_IMBE;
        for (auto& frame : state.imbe) {
            std::memcpy(frame.data(), null_frame, RAW_IMBE_LENGTH_BYTES);
        }
        return state;
    }

    /**
     * @brief Queues a pair of silence LDUs around a call boundary.
     * @param lane_key Destination mux lane.
     * @param call_key Per-call key.
     * @param header Message header to apply.
     * @param encrypted Whether encrypted silence pattern should be used.
     * @param start_with_ldu2 Whether the first silence frame should be LDU2.
     */
    void queue_silence_ldu_pair(const std::string& lane_key, const std::string& call_key,
        const P25MessageHdr& header, bool encrypted, bool start_with_ldu2) {
        P25CallState silence_state = build_silence_state(header, encrypted);

        OutboundFrame first;
        first.call_key = call_key;
        first.end_of_call = false;
        first.payload = build_ldu_payload(silence_state, start_with_ldu2);
        schedule_mux_frame(lane_key, call_key, std::move(first));

        OutboundFrame second;
        second.call_key = call_key;
        second.end_of_call = false;
        second.payload = build_ldu_payload(silence_state, !start_with_ldu2);
        schedule_mux_frame(lane_key, call_key, std::move(second));
    }

    struct SyntheticEndRequest {
        std::string call_key;
        std::string lane_key;
        long source_tgid = 0;
        bool encrypted = false;
        bool start_with_ldu2 = false;
        bool header_valid = false;
        P25MessageHdr header;
    };

    /**
     * @brief Creates a synthetic end request from the current call mux state.
     * @param call_key The call key for the request.
     * @param state The current call mux state.
     * @returns SyntheticEndRequest The constructed synthetic end request.
     */
    SyntheticEndRequest make_synthetic_end_request_locked(const std::string& call_key, const CallMuxState& state) {
        SyntheticEndRequest req;
        req.call_key = call_key;
        req.lane_key = state.lane_key;
        req.source_tgid = state.source_tgid;
        req.encrypted = state.encrypted;
        req.start_with_ldu2 = state.next_is_ldu2;
        req.header_valid = state.header_valid;
        req.header = state.header;
        return req;
    }

    /**
     * @brief Updates the call mux state based on voice frame information.
     * @param call_key The call key for the state to update.
     * @param tgid_call_key TGID fallback key for call_end correlation.
     * @param lane_key The lane key for the state to update.
     * @param source_tgid The source talkgroup ID.
     * @param header The message header to apply.
     * @param encrypted Whether the call is encrypted.
     * @param next_is_ldu2 Whether the next frame is an LDU2.
     */
    void update_call_mux_state_from_voice(const std::string& call_key, const std::string& tgid_call_key, const std::string& lane_key,
        long source_tgid, const P25MessageHdr& header, bool encrypted, bool next_is_ldu2) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        const auto now = std::chrono::steady_clock::now();

        CallMuxState& state = call_mux_state[call_key];
        state.lane_key = lane_key;
        state.tgid_call_key = tgid_call_key;
        state.source_tgid = source_tgid;
        state.header = header;
        state.header_valid = true;
        state.encrypted = encrypted;
        state.next_is_ldu2 = next_is_ldu2;
        state.last_activity = now;
        state.synthetic_end_queued = false;
        if (!state.ended) {
            state.active = (mux_lane_state[lane_key].active_call_key == call_key);
        }

        if (!tgid_call_key.empty()) {
            tgid_call_key_to_call_key[tgid_call_key] = call_key;
        }
    }

    /**
     * @brief Removes a waiting call from the lane state.
     * @param lane The lane state to modify.
     * @param call_key The call key to remove from the waiting calls.
     */
    void remove_waiting_call_locked(MuxLaneState& lane, const std::string& call_key) {
        lane.waiting_calls.erase(
            std::remove(lane.waiting_calls.begin(), lane.waiting_calls.end(), call_key),
            lane.waiting_calls.end());
    }

    /**
     * @brief Resolves a tracked call key from a TGID fallback key.
     * @param tgid_call_key TGID fallback key.
     * @returns std::string Tracked call key, or empty when unavailable.
     */
    std::string resolve_tracked_call_key_for_tgid(const std::string& tgid_call_key) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        auto it = tgid_call_key_to_call_key.find(tgid_call_key);
        if (it == tgid_call_key_to_call_key.end()) {
            return "";
        }
        return it->second;
    }

    /**
     * @brief Erases a TGID fallback alias when it still points at the same call.
     * @param tgid_call_key TGID fallback key.
     * @param call_key Per-call key.
     */
    void erase_tgid_call_key_locked(const std::string& tgid_call_key, const std::string& call_key) {
        if (tgid_call_key.empty()) {
            return;
        }

        auto it = tgid_call_key_to_call_key.find(tgid_call_key);
        if (it != tgid_call_key_to_call_key.end() && it->second == call_key) {
            tgid_call_key_to_call_key.erase(it);
        }
    }

    /**
     * @brief Erases mux state and the associated TGID fallback alias.
     * @param call_key Per-call key.
     */
    void erase_call_mux_state_locked(const std::string& call_key) {
        auto it = call_mux_state.find(call_key);
        if (it == call_mux_state.end()) {
            return;
        }

        erase_tgid_call_key_locked(it->second.tgid_call_key, call_key);
        call_mux_state.erase(it);
    }

    /**
     * @brief Erases call tracking information for a given call and lane.
     * @param call_key The call key to erase.
     * @param lane_key The lane key associated with the call.
     */
    void erase_call_tracking_locked(const std::string& call_key, const std::string& lane_key) {
        auto lane_it = mux_lane_state.find(lane_key);
        if (lane_it != mux_lane_state.end()) {
            remove_waiting_call_locked(lane_it->second, call_key);
            if (lane_it->second.active_call_key == call_key) {
                lane_it->second.active_call_key.clear();
            }

            if (lane_it->second.active_call_key.empty() && lane_it->second.waiting_calls.empty()) {
                mux_lane_state.erase(lane_it);
            }
        }

        erase_call_mux_state_locked(call_key);
        mux_buffered_frames.erase(call_key);
    }

    /**
     * @brief Injects a synthetic end request into the stream.
     * @param req The synthetic end request to inject.
     * @param reason The reason for the synthetic end injection.
     */
    void inject_synthetic_end_request(const SyntheticEndRequest& req, const char* reason) {
        P25CallState state;
        bool have_state = false;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            auto it = p25_call_state.find(req.call_key);
            if (it != p25_call_state.end()) {
                state = it->second;
                p25_call_state.erase(it);
                have_state = true;
            }
        }

        P25MessageHdr header;
        if (have_state) {
            header = state.header;
        } else if (req.header_valid) {
            header = req.header;
        } else {
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: synthetic end skipped due to missing header"
                                       << ", callKey = " << req.call_key
                                       << ", lane = " << req.lane_key
                                       << ", reason = " << reason;
            return;
        }

        if (have_state && state.imbeCount > 0U) {
            const uint8_t* null_frame = req.encrypted ? ENCRYPTED_NULL_IMBE : NULL_IMBE;
            while (state.imbeCount < 9U) {
                std::memcpy(state.imbe[state.imbeCount].data(), null_frame, RAW_IMBE_LENGTH_BYTES);
                state.imbeCount++;
            }

            OutboundFrame ldu_frame;
            ldu_frame.call_key = req.call_key;
            ldu_frame.end_of_call = false;
            ldu_frame.payload = build_ldu_payload(state, req.start_with_ldu2);
            schedule_mux_frame(req.lane_key, req.call_key, std::move(ldu_frame));
        }

        queue_silence_ldu_pair(req.lane_key, req.call_key, header, req.encrypted, req.start_with_ldu2);

        OutboundFrame frame;
        frame.call_key = req.call_key;
        frame.payload = build_tdu_payload(header);
        frame.end_of_call = true;
        schedule_mux_frame(req.lane_key, req.call_key, std::move(frame));
        mark_mux_call_ended(req.call_key, req.lane_key);

        BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: injected synthetic end"
                                   << ", reason = " << reason
                                   << ", callKey = " << req.call_key
                                   << ", lane = " << req.lane_key
                                   << ", sourceTg = " << req.source_tgid;
    }

    /**
     * @brief Reaps orphaned calls that have exceeded the configured timeout.
     * This function checks the last activity timestamp of each call in the mux state.
     * If a call has not had any activity for longer than the orphanCallTimeoutMs,
     * it is considered orphaned and a synthetic end request is generated for it.
     * Additionally, calls that have ended and exceeded the endedCallCleanupMs are cleaned up from
     * the mux state to free resources.
     */
    void reap_orphan_calls() {
        const auto now = std::chrono::steady_clock::now();
        const auto orphan_after = std::chrono::milliseconds(fne_config.orphanCallTimeoutMs);
        const auto cleanup_after = std::chrono::milliseconds(fne_config.endedCallCleanupMs);

        std::vector<SyntheticEndRequest> orphaned;
        std::vector<std::pair<std::string, std::string>> stale_ended;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(mux_mutex);

            for (auto& pair : call_mux_state) {
                const std::string& call_key = pair.first;
                CallMuxState& state = pair.second;

                if (state.last_activity.time_since_epoch().count() == 0) {
                    continue;
                }

                const auto age = now - state.last_activity;

                if (!state.ended && !state.synthetic_end_queued && age > orphan_after) {
                    state.synthetic_end_queued = true;
                    orphaned.push_back(make_synthetic_end_request_locked(call_key, state));
                    continue;
                }

                if (state.ended && age > cleanup_after) {
                    stale_ended.emplace_back(call_key, state.lane_key);
                }
            }

            for (const auto& stale : stale_ended) {
                erase_call_tracking_locked(stale.first, stale.second);
            }
        }

        for (const auto& req : orphaned) {
            inject_synthetic_end_request(req, "orphan-timeout");
        }
    }

    /**
     * @brief Derives the service options byte based on the call properties.
     * @param call Pointer to the Call object.
     * @returns uint8_t The derived service options byte.
     */
    uint8_t derive_service_options(Call* call) const {
        uint8_t service_options = 0x00U;
        if (call->get_emergency()) {
            service_options |= 0x80U;
        }

        if (call->get_encrypted()) {
            service_options |= 0x40U;
        }

        const int priority = call->get_priority();
        if (priority > 0) {
            service_options |= (uint8_t)(priority & 0x07);
        }

        return service_options;
    }

    /**
     * @brief Resolves destination TGID using route override when configured.
     * @param route Pointer to the matched route.
     * @param source_tgid Source talkgroup from trunk-recorder.
     * @returns uint32_t Destination TGID for FNE payloads.
     */
    uint32_t resolve_dst_tgid(const Route* route, long source_tgid) const {
        const long dst_tgid = (route && route->dstTgid > 0) ? route->dstTgid : source_tgid;
        return (uint32_t)(dst_tgid < 0 ? 0 : dst_tgid) & 0x00FFFFFFU;
    }

    /**
     * @brief Resolves a lane key for the call, preferring tracked mux state.
     * @param call_key Per-call key.
     * @param fallback Lane key calculated from current route and TGID.
     * @returns std::string Lane key used by the mux scheduler.
     */
    std::string resolve_lane_key_for_call(const std::string& call_key, const std::string& fallback) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        auto it = call_mux_state.find(call_key);
        if (it != call_mux_state.end() && !it->second.lane_key.empty()) {
            return it->second.lane_key;
        }
        return fallback;
    }

    /**
     * @brief Checks whether a call has mux tracking state.
     * @param call_key Per-call key.
     * @returns bool True if call exists in mux scheduler state.
     */
    bool has_mux_call_state(const std::string& call_key) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        return call_mux_state.find(call_key) != call_mux_state.end();
    }

    /**
     * @brief Buffers a frame for a queued call, dropping oldest on overflow.
     * @param call_key Per-call key.
     * @param frame Frame to buffer.
     */
    void buffer_mux_frame_locked(const std::string& call_key, OutboundFrame frame) {
        std::deque<OutboundFrame>& frames = mux_buffered_frames[call_key];
        if (frames.size() >= max_queue_depth) {
            frames.pop_front();
            dropped_mux_frames++;
            if ((dropped_mux_frames % 100U) == 0U) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: mux buffer overflow, dropped frames = " << dropped_mux_frames;
            }
        }

        frames.push_back(std::move(frame));
    }

    /**
     * @brief Enqueues buffered frames for an activated call into outbound queue.
     * @param call_key Per-call key.
     */
    void flush_mux_buffered_frames_locked(const std::string& call_key) {
        auto it = mux_buffered_frames.find(call_key);
        if (it == mux_buffered_frames.end()) {
            return;
        }

        // Preserve complete queued-call audio: replay every buffered frame in FIFO order.
        while (!it->second.empty()) {
            enqueue_frame(std::move(it->second.front()));
            it->second.pop_front();
        }

        mux_buffered_frames.erase(it);
    }

    /**
     * @brief Marks lane completion and promotes queued calls in FIFO order.
     * @param lane_key Lane key.
     * @param finished_call_key Just-finished active call.
     */
    void complete_lane_and_promote_locked(const std::string& lane_key, const std::string& finished_call_key) {
        auto lane_it = mux_lane_state.find(lane_key);
        if (lane_it == mux_lane_state.end()) {
            erase_call_mux_state_locked(finished_call_key);
            mux_buffered_frames.erase(finished_call_key);
            return;
        }

        MuxLaneState& lane = lane_it->second;
        if (lane.active_call_key == finished_call_key) {
            lane.active_call_key.clear();
        }

        erase_call_mux_state_locked(finished_call_key);
        mux_buffered_frames.erase(finished_call_key);

        while (lane.active_call_key.empty()) {
            if (lane.waiting_calls.empty()) {
                break;
            }

            const std::string next_call_key = lane.waiting_calls.front();
            lane.waiting_calls.pop_front();

            auto next_it = call_mux_state.find(next_call_key);
            if (next_it == call_mux_state.end()) {
                mux_buffered_frames.erase(next_call_key);
                continue;
            }

            next_it->second.active = true;
            next_it->second.queued = false;
            next_it->second.last_activity = std::chrono::steady_clock::now();
            lane.active_call_key = next_call_key;

            flush_mux_buffered_frames_locked(next_call_key);

            const bool next_ended = next_it->second.ended;
            if (!next_ended) {
                break;
            }

            lane.active_call_key.clear();
            erase_call_mux_state_locked(next_call_key);
            mux_buffered_frames.erase(next_call_key);
        }

        if (lane.active_call_key.empty() && lane.waiting_calls.empty()) {
            mux_lane_state.erase(lane_it);
        }
    }

    /**
     * @brief Schedules a frame into active lane or queues it if lane is busy.
     * @param lane_key Destination lane key.
     * @param call_key Per-call key.
     * @param frame Outbound frame to schedule.
     */
    void schedule_mux_frame(const std::string& lane_key, const std::string& call_key, OutboundFrame frame) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        const auto now = std::chrono::steady_clock::now();

        frame.lane_key = lane_key;
        frame.dst_tgid = extract_dst_tgid_from_payload(frame.payload);

        CallMuxState& call_state = call_mux_state[call_key];
        call_state.lane_key = lane_key;

        MuxLaneState& lane = mux_lane_state[lane_key];

        if (lane.active_call_key.empty()) {
            lane.active_call_key = call_key;
            call_state.active = true;
            call_state.queued = false;
        }

        if (lane.active_call_key == call_key) {
            call_state.ended = false;
            call_state.active = true;
            call_state.queued = false;
            call_state.last_activity = now;
            enqueue_frame(std::move(frame));
            return;
        }

        if (!call_state.queued) {
            lane.waiting_calls.push_back(call_key);
            call_state.queued = true;
            call_state.active = false;
            call_state.ended = false;
        }

        // Track queued-call freshness so stale promotion can recover if call_end
        // arrives without additional voice callbacks for this call.
        call_state.last_activity = now;
        call_state.buffered_frames++;

        if (!call_state.buffered_log_sent) {
            call_state.buffered_log_sent = true;
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: mux lane buffering call behind active call"
                                       << ", lane = " << lane_key
                                       << ", callKey = " << call_key
                                       << ", activeCallKey = " << lane.active_call_key
                                       << ", waiting = " << lane.waiting_calls.size()
                                       << ", dstTg = " << frame.dst_tgid
                                       << ", endOfCall = " << frame.end_of_call;
        }

        buffer_mux_frame_locked(call_key, std::move(frame));
    }

    /**
     * @brief Promotes queued calls if active call appears stale and blocks a lane.
     */
    void promote_stale_mux_lanes() {
        std::lock_guard<std::mutex> lock(mux_mutex);
        const auto now = std::chrono::steady_clock::now();
        const auto stale_after = std::chrono::milliseconds(mux_stale_call_ms);
        const auto force_after = std::chrono::milliseconds(mux_force_call_ms);
        std::vector<std::pair<std::string, std::string>> stale_lanes;

        for (const auto& lane_pair : mux_lane_state) {
            const std::string& lane_key = lane_pair.first;
            const MuxLaneState& lane = lane_pair.second;

            if (lane.active_call_key.empty() || lane.waiting_calls.empty()) {
                continue;
            }

            auto call_it = call_mux_state.find(lane.active_call_key);
            if (call_it == call_mux_state.end()) {
                stale_lanes.emplace_back(lane_key, lane.active_call_key);
                continue;
            }

            const auto& last = call_it->second.last_activity;
            if (last.time_since_epoch().count() == 0) {
                stale_lanes.emplace_back(lane_key, lane.active_call_key);
                continue;
            }

            const bool ended = call_it->second.ended;
            const auto threshold = ended ? stale_after : force_after;
            const bool owner_has_queued = queue_has_frame_for_call_locked(lane.active_call_key);
            const bool owner_has_sendable = queue_has_sendable_frame_for_call_locked(lane.active_call_key, now);
            const bool owner_has_dispatched = has_pending_dispatch_for_call(lane.active_call_key);

            if (!owner_has_dispatched && (!owner_has_queued || !owner_has_sendable)) {
                stale_lanes.emplace_back(lane_key, lane.active_call_key);
                continue;
            }

            if (now - last > threshold) {
                stale_lanes.emplace_back(lane_key, lane.active_call_key);
            }
        }

        for (const auto& stale : stale_lanes) {
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: promoting stale mux active call"
                                       << ", lane = " << stale.first
                                       << ", callKey = " << stale.second
                                       << ", waiting = " << mux_lane_state[stale.first].waiting_calls.size();
            complete_lane_and_promote_locked(stale.first, stale.second);
        }
    }

    /**
     * @brief Marks the call ended; advances lane if the call was active.
     * @param call_key Per-call key.
     * @param lane_key Lane key for the call.
     */
    void mark_mux_call_ended(const std::string& call_key, const std::string& lane_key) {
        std::lock_guard<std::mutex> lock(mux_mutex);
        auto call_it = call_mux_state.find(call_key);
        if (call_it == call_mux_state.end()) {
            return;
        }

        call_it->second.ended = true;
        call_it->second.synthetic_end_queued = false;
        call_it->second.last_activity = std::chrono::steady_clock::now();

        if (call_it->second.active) {
            complete_lane_and_promote_locked(lane_key, call_key);
        }
    }

    /**
     * @brief Builds the P25 message header based on the call and system information.
     * @param call Pointer to the Call object.
     * @param system Pointer to the System object.
     * @param effective_src The effective source ID.
     * @returns P25MessageHdr The constructed P25 message header.
     */
    P25MessageHdr build_message_header(Call* call, System* system, uint32_t effective_src, long source_tgid, const Route* route) const {
        P25MessageHdr header;
        header.lco = P25_LCO_GROUP;

        header.srcId = effective_src & 0x00FFFFFFU;
        header.dstId = resolve_dst_tgid(route, source_tgid);

        header.sysId = static_cast<uint16_t>(system->get_sys_id() & 0xFFFFU);

        header.mfid = MFG_STANDARD;

        header.netId = (uint32_t)(system->get_wacn() & 0x00FFF000UL);
        header.netId |= (uint32_t)(system->get_sys_id() & 0x0000FFFFUL);

        header.lsd1 = 0x00U;
        header.lsd2 = 0x00U;

        header.serviceOptions = derive_service_options(call);

        header.algId = call->get_encrypted() ? 0x84U : ALGO_UNENCRYPT;
        header.kId = 0x0000U;

        header.mi.fill(0x00U);
        
        return header;
    }

    /**
     * @brief Creates a P25 message header in the provided buffer.
     * @param buffer Pointer to the buffer where the header will be written.
     * @param hdr Reference to the P25MessageHdr structure containing header information.
     * @param duid The Data Unit ID.
     * @param frame_type The frame type.
     */
    void create_p25_message_hdr(uint8_t* buffer, const P25MessageHdr& hdr, uint8_t duid, uint8_t frame_type) const {
        std::memcpy(buffer, TAG_P25_DATA, 4U);

        buffer[4U] = hdr.lco;

        uint32_t srcId = hdr.srcId;
        SET_UINT24(srcId, buffer, 5U);
        uint32_t dstId = hdr.dstId;
        SET_UINT24(dstId, buffer, 8U);

        SET_UINT16(hdr.sysId, buffer, 11U);

        buffer[14U] = NET_CTRL_SWITCH_OVER;
        buffer[15U] = hdr.mfid;

        uint32_t netId = hdr.netId;
        SET_UINT24(netId, buffer, 16U);

        buffer[20U] = hdr.lsd1;
        buffer[21U] = hdr.lsd2;
        buffer[22U] = duid;

        if (frame_type != FrameType::TERMINATOR) {
            buffer[180U] = frame_type;
        }
    }

    /**
     * @brief Builds the LDU1 payload based on the call state.
     * @param state Reference to the P25CallState structure containing call information.
     * @returns std::vector<uint8_t> The constructed LDU1 payload.
     */
    std::vector<uint8_t> build_ldu1_payload(const P25CallState& state) const {
        std::vector<uint8_t> buffer(P25_LDU1_PACKET_LENGTH + PACKET_PAD, 0x00U);
        create_p25_message_hdr(buffer.data(), state.header, DUID::LDU1, FrameType::DATA_UNIT);

        size_t offset = MSG_HDR_SIZE;

        // LDU1 Voice 1: frame type, RSSI placeholder, IMBE at +10
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE1;
        std::memcpy(buffer.data() + offset + 10U, state.imbe[0U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE1_FRAME_LENGTH_BYTES;

        // LDU1 Voice 2: IMBE at +1
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE2;
        std::memcpy(buffer.data() + offset + 1U, state.imbe[1U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE2_FRAME_LENGTH_BYTES;

        // LDU1 Voice 3: LCO/MFID/Service at +1..3, IMBE at +5
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE3;
        buffer[offset + 1U] = state.header.lco;
        buffer[offset + 2U] = state.header.mfid;
        buffer[offset + 3U] = state.header.serviceOptions;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[2U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE3_FRAME_LENGTH_BYTES;

        // LDU1 Voice 4: DST TGID at +1..3, IMBE at +5
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE4;
        uint32_t dstId = state.header.dstId & 0x00FFFFFFU;
        SET_UINT24(dstId, buffer, offset + 1U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[3U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE4_FRAME_LENGTH_BYTES;

        // LDU1 Voice 5: SRC ID at +1..3, IMBE at +5
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE5;
        uint32_t srcId = state.header.srcId & 0x00FFFFFFU;
        SET_UINT24(srcId, buffer, offset + 1U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[4U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE5_FRAME_LENGTH_BYTES;

        // LDU1 Voice 6-8: IMBE at +5 (RS bytes left zero)
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE6;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[5U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE6_FRAME_LENGTH_BYTES;

        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE7;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[6U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE7_FRAME_LENGTH_BYTES;

        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE8;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[7U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE8_FRAME_LENGTH_BYTES;

        // LDU1 Voice 9: LSD1/LSD2 at +1..2, IMBE at +4
        buffer[offset + 0U] = DFSIFrameType::LDU1_VOICE9;
        buffer[offset + 1U] = state.header.lsd1;
        buffer[offset + 2U] = state.header.lsd2;
        std::memcpy(buffer.data() + offset + 4U, state.imbe[8U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU1_VOICE9_FRAME_LENGTH_BYTES;

        buffer[23U] = (uint8_t)(offset & 0xFFU);
        return buffer;
    }

    /**
     * @brief Builds the LDU2 payload based on the call state.
     * @param state Reference to the P25CallState structure containing call information.
     * @returns std::vector<uint8_t> The constructed LDU2 payload.
     */
    std::vector<uint8_t> build_ldu2_payload(const P25CallState& state) const {
        std::vector<uint8_t> buffer(P25_LDU2_PACKET_LENGTH + PACKET_PAD, 0x00U);
        create_p25_message_hdr(buffer.data(), state.header, DUID::LDU2, FrameType::DATA_UNIT);

        size_t offset = MSG_HDR_SIZE;

        // LDU2 Voice 10: frame type, RSSI placeholder, IMBE at +10
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE10;
        std::memcpy(buffer.data() + offset + 10U, state.imbe[0U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE10_FRAME_LENGTH_BYTES;

        // LDU2 Voice 11: IMBE at +1
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE11;
        std::memcpy(buffer.data() + offset + 1U, state.imbe[1U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE11_FRAME_LENGTH_BYTES;

        // LDU2 Voice 12-14: MI chunks at +1..3, IMBE at +5
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE12;
        std::memcpy(buffer.data() + offset + 1U, state.header.mi.data(), 3U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[2U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE12_FRAME_LENGTH_BYTES;

        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE13;
        std::memcpy(buffer.data() + offset + 1U, state.header.mi.data() + 3U, 3U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[3U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE13_FRAME_LENGTH_BYTES;

        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE14;
        std::memcpy(buffer.data() + offset + 1U, state.header.mi.data() + 6U, 3U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[4U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE14_FRAME_LENGTH_BYTES;

        // LDU2 Voice 15: ALG/KID at +1..3, IMBE at +5
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE15;
        buffer[offset + 1U] = state.header.algId;
        SET_UINT16(state.header.kId, buffer.data(), offset + 2U);
        std::memcpy(buffer.data() + offset + 5U, state.imbe[5U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE15_FRAME_LENGTH_BYTES;

        // LDU2 Voice 16-17: IMBE at +5 (RS bytes left zero)
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE16;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[6U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE16_FRAME_LENGTH_BYTES;

        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE17;
        std::memcpy(buffer.data() + offset + 5U, state.imbe[7U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE17_FRAME_LENGTH_BYTES;

        // LDU2 Voice 18: LSD1/LSD2 at +1..2, IMBE at +4
        buffer[offset + 0U] = DFSIFrameType::LDU2_VOICE18;
        buffer[offset + 1U] = state.header.lsd1;
        buffer[offset + 2U] = state.header.lsd2;
        std::memcpy(buffer.data() + offset + 4U, state.imbe[8U].data(), RAW_IMBE_LENGTH_BYTES);
        offset += DFSI_LDU2_VOICE18_FRAME_LENGTH_BYTES;

        buffer[23U] = (uint8_t)(offset & 0xFFU);
        return buffer;
    }

    /**
     * @brief Builds the LDU payload based on the call state and whether it's LDU1 or LDU2.
     * @param state Reference to the P25CallState structure containing call information.
     * @param ldu2 Boolean indicating whether to build LDU2 (true) or LDU1 (false).
     * @returns std::vector<uint8_t> The constructed LDU payload.
     */
    std::vector<uint8_t> build_ldu_payload(const P25CallState& state, bool ldu2) const {
        return ldu2 ? build_ldu2_payload(state) : build_ldu1_payload(state);
    }

    /**
     * @brief Builds the TDU payload based on the message metadata.
     * @param hdr Reference to the P25MessageHdr structure containing message information.
     * @returns std::vector<uint8_t> The constructed TDU payload.
     */
    std::vector<uint8_t> build_tdu_payload(const P25MessageHdr& hdr) const {
        std::vector<uint8_t> buffer(MSG_HDR_SIZE + PACKET_PAD, 0x00U);
        create_p25_message_hdr(buffer.data(), hdr, DUID::TDU, FrameType::TERMINATOR);
        buffer[23U] = (uint8_t)(MSG_HDR_SIZE & 0xFFU);
        return buffer;
    }

    /**
     * @brief Extracts destination TGID from a P25 payload header.
     * @param payload Frame payload.
     * @returns uint32_t Destination TGID, or 0 when unavailable.
     */
    uint32_t extract_dst_tgid_from_payload(const std::vector<uint8_t>& payload) const {
        if (payload.size() < MSG_HDR_SIZE || std::memcmp(payload.data(), TAG_P25_DATA, 4U) != 0) {
            return 0U;
        }

        return (((uint32_t)(payload[8U]) << 16) |
                ((uint32_t)(payload[9U]) << 8) |
                ((uint32_t)(payload[10U]) << 0)) & 0x00FFFFFFU;
    }

    /**
     * @brief Finds a route based on the talkgroup ID, short name, and encryption status.
     * @param tgid The talkgroup ID.
     * @param short_name The short name of the route.
     * @param encrypted Boolean indicating whether the call is encrypted.
     * @returns const Route* Pointer to the matching Route, or nullptr if not found.
     */
    const Route *find_route(long tgid, const std::string& short_name, bool encrypted) const {
        for (const auto &route : routes) {
            if (!route.short_name.empty() && route.short_name != short_name) {
                continue;
            }

            if (route.tgid != 0 && route.tgid != tgid) {
                continue;
            }

            return &route;
        }
        return nullptr;
    }

    /**
     * @brief Enqueues an outbound frame for transmission.
     * @param frame The OutboundFrame to enqueue.
     */
    void enqueue_frame(OutboundFrame frame) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        std::string lane_key = frame.lane_key;
        if (lane_key.empty()) {
            lane_key = "__default";
            frame.lane_key = lane_key;
        }

        const FrameLogInfo queued_info = make_frame_log_info(frame);
        if (queue_size >= max_queue_depth) {
            bool dropped = false;

            auto own_it = lane_queues.find(lane_key);
            if (own_it != lane_queues.end() && !own_it->second.empty()) {
                OutboundFrame dropped_frame = std::move(own_it->second.front());
                own_it->second.pop_front();
                queue_size--;
                adjust_drop_accounting_locked(dropped_frame);
                note_frame_dropped(make_frame_log_info(dropped_frame), "outbound queue overflow");
                if (own_it->second.empty()) {
                    lane_queues.erase(own_it);
                    lane_in_rr.erase(lane_key);
                    auto rr_it = std::find(lane_rr.begin(), lane_rr.end(), lane_key);
                    if (rr_it != lane_rr.end()) {
                        lane_rr.erase(rr_it);
                    }
                }
                dropped = true;
            }

            if (!dropped) {
                for (const auto& rr_lane : lane_rr) {
                    auto it = lane_queues.find(rr_lane);
                    if (it != lane_queues.end() && !it->second.empty()) {
                        OutboundFrame dropped_frame = std::move(it->second.front());
                        it->second.pop_front();
                        queue_size--;
                        adjust_drop_accounting_locked(dropped_frame);
                        note_frame_dropped(make_frame_log_info(dropped_frame), "outbound queue overflow");
                        if (it->second.empty()) {
                            lane_queues.erase(it);
                            lane_in_rr.erase(rr_lane);
                            auto rr_it = std::find(lane_rr.begin(), lane_rr.end(), rr_lane);
                            if (rr_it != lane_rr.end()) {
                                lane_rr.erase(rr_it);
                            }
                        }
                        dropped = true;
                        break;
                    }
                }
            }

            if (!dropped) {
                return;
            }

            dropped_frames++;
            if ((dropped_frames % 100U) == 0U) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: queue overflow, dropped frames=" << dropped_frames;
            }
        }

        std::deque<OutboundFrame>& lane_queue = lane_queues[lane_key];
        if (!frame.end_of_call) {
            pending_non_end_frames[frame.call_key]++;
        }
        lane_queue.push_back(std::move(frame));
        queue_size++;
        if (net_state != NET_STAT_RUNNING && queue_size == 1U) {
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: outbound queue started while FNE session is not running"
                                       << ", state = " << net_state_name(net_state)
                                       << ", lane = " << queued_info.lane_key
                                       << ", callKey = " << queued_info.call_key
                                       << ", dstTg = " << queued_info.dst_tgid
                                       << ", payloadBytes = " << queued_info.payload_size;
        }
        note_outbound_queued(queued_info);

        if (lane_in_rr.insert(lane_key).second) {
            lane_rr.push_back(lane_key);
        }
    }

    /**
     * @brief Requeues an outbound frame at the back to retry later.
     * @param frame The OutboundFrame to requeue.
     */
    void requeue_frame_back(OutboundFrame frame) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        std::string lane_key = frame.lane_key;
        if (lane_key.empty()) {
            lane_key = "__default";
            frame.lane_key = lane_key;
        }

        if (queue_size >= max_queue_depth) {
            bool dropped = false;

            auto own_it = lane_queues.find(lane_key);
            if (own_it != lane_queues.end() && !own_it->second.empty()) {
                OutboundFrame dropped_frame = std::move(own_it->second.back());
                own_it->second.pop_back();
                queue_size--;
                adjust_drop_accounting_locked(dropped_frame);
                if (own_it->second.empty()) {
                    lane_queues.erase(own_it);
                    lane_in_rr.erase(lane_key);
                    auto rr_it = std::find(lane_rr.begin(), lane_rr.end(), lane_key);
                    if (rr_it != lane_rr.end()) {
                        lane_rr.erase(rr_it);
                    }
                }
                dropped = true;
            }

            if (!dropped) {
                for (auto rr_it = lane_rr.rbegin(); rr_it != lane_rr.rend(); ++rr_it) {
                    auto it = lane_queues.find(*rr_it);
                    if (it != lane_queues.end() && !it->second.empty()) {
                        OutboundFrame dropped_frame = std::move(it->second.back());
                        it->second.pop_back();
                        queue_size--;
                        adjust_drop_accounting_locked(dropped_frame);
                        if (it->second.empty()) {
                            lane_in_rr.erase(*rr_it);
                            auto erase_it = std::find(lane_rr.begin(), lane_rr.end(), *rr_it);
                            if (erase_it != lane_rr.end()) {
                                lane_rr.erase(erase_it);
                            }
                            lane_queues.erase(it);
                        }
                        dropped = true;
                        break;
                    }
                }
            }

            if (!dropped) {
                return;
            }

            dropped_frames++;
        }

        std::deque<OutboundFrame>& lane_queue = lane_queues[lane_key];
        if (!frame.end_of_call) {
            pending_non_end_frames[frame.call_key]++;
        }
        lane_queue.push_back(std::move(frame));
        queue_size++;

        if (lane_in_rr.insert(lane_key).second) {
            lane_rr.push_back(lane_key);
        }
    }

    /**
     * @brief Checks whether queued non-end frames still exist for a call.
     * @param call_key Per-call key.
     * @returns bool True when unsent non-end frames remain in the outbound queue.
     */
    bool has_pending_non_end_frames_for_call_locked(const std::string& call_key) const {
        auto it = pending_non_end_frames.find(call_key);
        return it != pending_non_end_frames.end() && it->second > 0U;
    }

    /**
     * @brief Checks whether any queued frames exist for a call.
     * @param call_key Per-call key.
     * @returns bool True when any unsent frames remain in the outbound queue.
     */
    bool queue_has_frame_for_call_locked(const std::string& call_key) const {
        for (const auto& lane_pair : lane_queues) {
            for (const auto& frame : lane_pair.second) {
                if (frame.call_key == call_key) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @brief Checks whether at least one queued frame for the call is currently sendable.
     * @param call_key Per-call key.
     * @param now Current time point.
     * @returns bool True when a queued frame can be popped right now.
     */
    bool queue_has_sendable_frame_for_call_locked(const std::string& call_key,
        const std::chrono::steady_clock::time_point& now) const {
        for (const auto& lane_pair : lane_queues) {
            for (const auto& frame : lane_pair.second) {
                if (frame.call_key != call_key) {
                    continue;
                }

                if (!frame.end_of_call) {
                    return is_non_end_frame_ready(call_key, now);
                }

                return true;
            }
        }

        return false;
    }

    /**
     * @brief Ensures a lane with queued frames is present in the round-robin list.
     * @param lane_key Lane key to refresh.
     */
    void ensure_lane_rr_entry_locked(const std::string& lane_key) {
        auto it = lane_queues.find(lane_key);
        if (it == lane_queues.end() || it->second.empty()) {
            lane_in_rr.erase(lane_key);
            return;
        }

        lane_in_rr.insert(lane_key);
        if (std::find(lane_rr.begin(), lane_rr.end(), lane_key) == lane_rr.end()) {
            lane_rr.push_back(lane_key);
        }
    }

    /**
     * @brief Removes a lane from the round-robin list.
     * @param lane_key Lane key to remove.
     */
    void remove_lane_rr_entry_locked(const std::string& lane_key) {
        lane_in_rr.erase(lane_key);
        auto rr_it = std::find(lane_rr.begin(), lane_rr.end(), lane_key);
        if (rr_it != lane_rr.end()) {
            lane_rr.erase(rr_it);
        }
    }

    /**
     * @brief Updates queue accounting after a frame has been popped.
     * @param frame Popped frame.
     */
    void account_popped_frame_locked(const OutboundFrame& frame) {
        if (frame.end_of_call) {
            return;
        }

        auto count_it = pending_non_end_frames.find(frame.call_key);
        if (count_it != pending_non_end_frames.end()) {
            if (count_it->second > 1U) {
                count_it->second--;
            } else {
                pending_non_end_frames.erase(count_it);
            }
        }
    }

    /**
     * @brief Pops the next ready queued frame for a specific call.
     * @param call_key Per-call key to drain.
     * @param now Current time point.
     * @param out Reference to the OutboundFrame where the popped frame will be stored.
     * @returns bool True if a frame was successfully popped.
     */
    bool pop_ready_frame_for_call_locked(const std::string& call_key,
        const std::chrono::steady_clock::time_point& now, OutboundFrame& out) {
        for (auto lane_it = lane_queues.begin(); lane_it != lane_queues.end(); ++lane_it) {
            std::deque<OutboundFrame>& frames = lane_it->second;
            for (auto frame_it = frames.begin(); frame_it != frames.end(); ++frame_it) {
                if (frame_it->call_key != call_key) {
                    continue;
                }

                if (!frame_it->end_of_call && !is_non_end_frame_ready(call_key, now)) {
                    return false;
                }

                const std::string lane_key = lane_it->first;
                out = std::move(*frame_it);
                frames.erase(frame_it);
                queue_size--;
                account_popped_frame_locked(out);

                if (frames.empty()) {
                    remove_lane_rr_entry_locked(lane_key);
                    lane_queues.erase(lane_it);
                } else {
                    ensure_lane_rr_entry_locked(lane_key);
                }

                return true;
            }
        }

        return false;
    }

    /**
     * @brief Increments in-flight dispatched frame count for a call.
     * @param call_key Per-call key.
     */
    void increment_pending_dispatch_for_call(const std::string& call_key) {
        if (call_key.empty()) {
            return;
        }

        std::lock_guard<std::mutex> lock(dispatch_accounting_mutex);
        pending_dispatched_frames[call_key]++;
    }

    /**
     * @brief Decrements in-flight dispatched frame count for a call.
     * @param call_key Per-call key.
     */
    void decrement_pending_dispatch_for_call(const std::string& call_key) {
        if (call_key.empty()) {
            return;
        }

        std::lock_guard<std::mutex> lock(dispatch_accounting_mutex);
        auto it = pending_dispatched_frames.find(call_key);
        if (it == pending_dispatched_frames.end()) {
            return;
        }

        if (it->second > 1U) {
            it->second--;
        } else {
            pending_dispatched_frames.erase(it);
        }
    }

    /**
     * @brief Checks whether a call has in-flight dispatched frames.
     * @param call_key Per-call key.
     * @returns bool True when frames are pending in sender workers.
     */
    bool has_pending_dispatch_for_call(const std::string& call_key) const {
        std::lock_guard<std::mutex> lock(dispatch_accounting_mutex);
        auto it = pending_dispatched_frames.find(call_key);
        return it != pending_dispatched_frames.end() && it->second > 0U;
    }

    /**
     * @brief Checks whether stream state for a call is stale enough to release dst ownership.
     * @param call_key Per-call key.
     * @param now Current time point.
     * @returns bool True when there is no active/expected near-term protocol send.
     */
    bool is_stream_state_stale_for_call_locked(const std::string& call_key,
        const std::chrono::steady_clock::time_point& now) const {
        std::lock_guard<std::mutex> stream_lock(stream_state_mutex);
        auto it = stream_state.find(call_key);
        if (it == stream_state.end()) {
            return true;
        }

        const auto next_send_at = it->second.next_protocol_send_at;
        if (next_send_at.time_since_epoch().count() == 0) {
            return false;
        }

        return now > (next_send_at + std::chrono::milliseconds(fne_config.pacedCallTimeoutMs));
    }

    /**
     * @brief Adjusts accounting for dropped frames, updating pending counts and active call mappings.
     * @param dropped_frame The OutboundFrame that was dropped.
     */
    void adjust_drop_accounting_locked(const OutboundFrame& dropped_frame) {
        if (!dropped_frame.end_of_call) {
            auto count_it = pending_non_end_frames.find(dropped_frame.call_key);
            if (count_it != pending_non_end_frames.end()) {
                if (count_it->second > 1U) {
                    count_it->second--;
                } else {
                    pending_non_end_frames.erase(count_it);
                }
            }
            return;
        }

        if (dropped_frame.dst_tgid != 0U) {
            auto active_it = dst_tgid_active_calls.find(dropped_frame.dst_tgid);
            if (active_it != dst_tgid_active_calls.end() && active_it->second == dropped_frame.call_key) {
                const bool has_queued = queue_has_frame_for_call_locked(dropped_frame.call_key);
                const bool has_dispatched = has_pending_dispatch_for_call(dropped_frame.call_key);
                const bool stream_stale = is_stream_state_stale_for_call_locked(dropped_frame.call_key, std::chrono::steady_clock::now());
                if (!has_queued && !has_dispatched && stream_stale) {
                    dst_tgid_active_calls.erase(active_it);
                }
            }
        }
    }

    /**
     * @brief Checks if a non-end frame is ready to be sent based on the call's next protocol send time.
     * @param call_key Per-call key.
     * @param now The current time point.
     * @returns bool True if the non-end frame is ready to be sent, false otherwise.
     */
    bool is_non_end_frame_ready(const std::string& call_key, const std::chrono::steady_clock::time_point& now) const {
        std::lock_guard<std::mutex> stream_lock(stream_state_mutex);
        auto it = stream_state.find(call_key);
        if (it == stream_state.end()) {
            return true;
        }

        const auto& next_send_at = it->second.next_protocol_send_at;
        if (next_send_at.time_since_epoch().count() == 0) {
            return true;
        }

        return now >= next_send_at;
    }

    /**
     * @brief Pops an outbound frame from the queue for transmission.
     * @param out Reference to the OutboundFrame where the popped frame will be stored.
     * @returns bool True if a frame was successfully popped, false if the queue was empty
     */
    bool pop_ready_frame(OutboundFrame& out, const std::chrono::steady_clock::time_point& now) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        if (queue_size == 0U || lane_rr.empty()) {
            return false;
        }

        size_t lanes_to_scan = lane_rr.size();
        while (lanes_to_scan-- > 0 && !lane_rr.empty()) {
            const std::string lane_key = lane_rr.front();
            lane_rr.pop_front();

            auto it = lane_queues.find(lane_key);
            if (it == lane_queues.end() || it->second.empty()) {
                lane_in_rr.erase(lane_key);
                continue;
            }

            const OutboundFrame& candidate = it->second.front();
            if (!candidate.end_of_call && !is_non_end_frame_ready(candidate.call_key, now)) {
                lane_rr.push_back(lane_key);
                continue;
            }

            const uint32_t candidate_dst_tgid = candidate.dst_tgid;
            const std::string candidate_call_key = candidate.call_key;
            if (candidate_dst_tgid != 0U) {
                auto active_it = dst_tgid_active_calls.find(candidate_dst_tgid);
                if (active_it != dst_tgid_active_calls.end() && active_it->second != candidate_call_key) {
                    const std::string owner_call_key = active_it->second;
                    const bool owner_has_queued = queue_has_frame_for_call_locked(owner_call_key);
                    const bool owner_has_sendable = queue_has_sendable_frame_for_call_locked(owner_call_key, now);
                    const bool owner_has_dispatched = has_pending_dispatch_for_call(owner_call_key);
                    const bool owner_stream_stale = is_stream_state_stale_for_call_locked(owner_call_key, now);
                    if ((!owner_has_queued && !owner_has_dispatched) ||
                        (owner_stream_stale && !owner_has_dispatched && !owner_has_sendable)) {
                        BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: releasing stale dstTg flush owner"
                                                   << ", dstTg = " << candidate_dst_tgid
                                                   << ", ownerCallKey = " << owner_call_key
                                                   << ", ownerQueued = " << owner_has_queued
                                                   << ", ownerSendable = " << owner_has_sendable
                                                   << ", ownerDispatched = " << owner_has_dispatched;
                        dst_tgid_active_calls.erase(active_it);
                    } else {
                        if (owner_has_sendable && !owner_has_dispatched &&
                            pop_ready_frame_for_call_locked(owner_call_key, now, out)) {
                            ensure_lane_rr_entry_locked(lane_key);
                            dst_tgid_owner_priority_frames++;
                            if (dst_tgid_owner_priority_frames == 1U || (dst_tgid_owner_priority_frames % 500U) == 0U) {
                                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: prioritizing dstTg owner queued frame"
                                                           << ", dstTg = " << candidate_dst_tgid
                                                           << ", ownerCallKey = " << owner_call_key
                                                           << ", waitingCallKey = " << candidate_call_key
                                                           << ", endOfCall = " << out.end_of_call
                                                           << ", priorityFrames = " << dst_tgid_owner_priority_frames;
                            }
                            return true;
                        }

                        dst_tgid_blocked_frames++;
                        const std::string block_key = make_dst_tgid_block_key(candidate_dst_tgid, owner_call_key, candidate_call_key);
                        uint64_t& blocked_for_pair = dst_tgid_blocked_call_counts[block_key];
                        blocked_for_pair++;
                        if (blocked_for_pair == 1U || (blocked_for_pair % 500U) == 0U || (dst_tgid_blocked_frames % 1000U) == 0U) {
                            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: dstTg owner blocking queued frame"
                                                       << ", dstTg = " << candidate_dst_tgid
                                                       << ", ownerCallKey = " << owner_call_key
                                                       << ", waitingCallKey = " << candidate_call_key
                                                       << ", ownerQueued = " << owner_has_queued
                                                       << ", ownerSendable = " << owner_has_sendable
                                                       << ", ownerDispatched = " << owner_has_dispatched
                                                       << ", pairBlockedFrames = " << blocked_for_pair
                                                       << ", blockedFrames = " << dst_tgid_blocked_frames;
                        }
                        lane_rr.push_back(lane_key);
                        continue;
                    }
                }
            }

            out = std::move(it->second.front());
            it->second.pop_front();
            queue_size--;

            if (out.dst_tgid != 0U) {
                auto active_it = dst_tgid_active_calls.find(out.dst_tgid);
                if (active_it == dst_tgid_active_calls.end()) {
                    dst_tgid_active_calls[out.dst_tgid] = out.call_key;
                    BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: acquired dstTg owner"
                                             << ", dstTg = " << out.dst_tgid
                                             << ", callKey = " << out.call_key
                                             << ", endOfCall = " << out.end_of_call;
                }
            }

            if (!out.end_of_call) {
                auto count_it = pending_non_end_frames.find(out.call_key);
                if (count_it != pending_non_end_frames.end()) {
                    if (count_it->second > 1U) {
                        count_it->second--;
                    } else {
                        pending_non_end_frames.erase(count_it);
                    }
                }
            }

            if (!it->second.empty()) {
                lane_rr.push_back(lane_key);
            } else {
                lane_in_rr.erase(lane_key);
                lane_queues.erase(it);
            }

            return true;
        }

        return false;
    }

    /**
     * @brief Releases destination TGID ownership after an end-of-call frame has been sent.
     * @param frame Sent outbound frame.
     */
    void release_dst_tgid_owner_for_sent_frame(const OutboundFrame& frame) {
        if (!frame.end_of_call || frame.dst_tgid == 0U) {
            return;
        }

        std::lock_guard<std::mutex> lock(queue_mutex);
        auto active_it = dst_tgid_active_calls.find(frame.dst_tgid);
        if (active_it != dst_tgid_active_calls.end() && active_it->second == frame.call_key) {
            dst_tgid_active_calls.erase(active_it);
            dst_tgid_owner_releases++;
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: released dstTg owner after TDU send"
                                    << ", dstTg = " << frame.dst_tgid
                                    << ", callKey = " << frame.call_key
                                    << ", releases = " << dst_tgid_owner_releases;
        } else {
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: TDU sent but dstTg owner was missing or changed"
                                       << ", dstTg = " << frame.dst_tgid
                                       << ", callKey = " << frame.call_key
                                       << ", currentOwner = " << ((active_it != dst_tgid_active_calls.end()) ? active_it->second : "");
        }

        const std::string block_prefix = std::to_string(frame.dst_tgid) + ":";
        for (auto it = dst_tgid_blocked_call_counts.begin(); it != dst_tgid_blocked_call_counts.end(); ) {
            if (it->first.compare(0U, block_prefix.size(), block_prefix) == 0) {
                it = dst_tgid_blocked_call_counts.erase(it);
            } else {
                ++it;
            }
        }

        clear_call_diagnostics(frame.call_key);
    }

    /**
     * @brief Generates a random stream ID for the session.
     * @returns uint32_t A random stream ID in the range [1, 0xFFFFFFFE].
     */
    uint32_t random_stream_id() {
        std::lock_guard<std::mutex> lock(rng_mutex);
        std::uniform_int_distribution<uint32_t> dist(1U, 0xFFFFFFFEU);
        return dist(rng);
    }

    /**
     * @brief Generates the next sequence number for RTP packets, wrapping around at RTP_END_OF_CALL_SEQ.
     * @param end_of_call Boolean indicating whether this is the end of a call.
     * @returns uint16_t The next sequence number.
     */
    uint16_t next_seq(bool end_of_call = false) {
        std::lock_guard<std::mutex> lock(seq_mutex);
        if (end_of_call) {
            return RTP_END_OF_CALL_SEQ;
        }
        
        const uint16_t seq = tx_seq;
        tx_seq = static_cast<uint16_t>(tx_seq + 1U);
        if (tx_seq >= RTP_END_OF_CALL_SEQ) {
            tx_seq = 0U;
        }

        return seq;
    }

    /**
     * @brief Reserves the next protocol send slot for a call at dispatch time.
     * @param frame Outbound frame that is about to be queued to a sender worker.
     */
    void reserve_dispatch_pacing_slot(const OutboundFrame& frame) {
        if (frame.end_of_call) {
            return;
        }

        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> stream_lock(stream_state_mutex);

        StreamState& state = stream_state[frame.call_key];
        if (state.streamId == 0U) {
            state.streamId = random_stream_id();
            state.timestampInit = false;
        }

        if (state.next_protocol_send_at.time_since_epoch().count() == 0 || state.next_protocol_send_at < now) {
            state.next_protocol_send_at = now + std::chrono::milliseconds(160);
            return;
        }

        state.next_protocol_send_at += std::chrono::milliseconds(160);
    }

    /**
     * @brief Picks a sender worker index using dst TGID lane affinity.
     * @param frame Outbound frame to dispatch.
     * @returns size_t Worker index.
     */
    size_t select_sender_worker_index(const OutboundFrame& frame) const {
        const std::string lane_key = frame.lane_key.empty() ? frame.call_key : frame.lane_key;
        return select_sender_worker_index_for_lane(lane_key);
    }

    /**
     * @brief Selects a worker index for a specific lane, keeping lane affinity sticky.
     * @param lane_key Destination lane key.
     * @returns size_t Worker index.
     */
    size_t select_sender_worker_index_for_lane(const std::string& lane_key) const {
        if (sender_workers.empty()) {
            return 0U;
        }

        {
            std::lock_guard<std::mutex> lock(sender_assignment_mutex);
            auto it = sender_lane_assignments.find(lane_key);
            if (it != sender_lane_assignments.end()) {
                return it->second;
            }
        }

        return 0U;
    }

    /**
     * @brief Starts sender worker threads for parallel lane-oriented protocol sends.
     */
    void start_sender_workers() {
        stop_sender_workers();

        const size_t worker_count = (size_t)(std::max<uint32_t>(1U, fne_config.sendWorkers));
        sender_workers.reserve(worker_count);
        sender_worker_lane_counts.assign(worker_count, 0U);

        for (size_t i = 0; i < worker_count; i++) {
            sender_workers.push_back(std::make_unique<SenderWorkerState>());
        }

        for (size_t i = 0; i < worker_count; i++) {
            sender_workers[i]->thread = std::thread(&DVMTRP25Stream::sender_worker_loop, this, i);
        }
    }

    /**
     * @brief Stops all sender worker threads and clears pending dispatch queues.
     */
    void stop_sender_workers() {
        for (auto& worker_state : sender_workers) {
            {
                std::lock_guard<std::mutex> lock(worker_state->mutex);
                worker_state->stop = true;
            }
            worker_state->cv.notify_all();
        }

        for (auto& worker_state : sender_workers) {
            if (worker_state->thread.joinable()) {
                worker_state->thread.join();
            }
        }

        sender_workers.clear();
        {
            std::lock_guard<std::mutex> lock(sender_assignment_mutex);
            sender_lane_assignments.clear();
        }
        sender_worker_lane_counts.clear();
    }

    /**
     * @brief Clears queued sender-dispatch frames without stopping workers.
     */
    void clear_sender_dispatch_queues() {
        std::vector<std::string> drained_call_keys;
        for (auto& worker_state : sender_workers) {
            std::lock_guard<std::mutex> lock(worker_state->mutex);
            while (!worker_state->queue.empty()) {
                drained_call_keys.push_back(worker_state->queue.front().call_key);
                worker_state->queue.pop_front();
            }
            worker_state->queue.clear();
        }

        for (const auto& call_key : drained_call_keys) {
            decrement_pending_dispatch_for_call(call_key);
        }

        std::lock_guard<std::mutex> accounting_lock(dispatch_accounting_mutex);
        pending_dispatched_frames.clear();

        if (!drained_call_keys.empty()) {
            reset_dropped_frames += drained_call_keys.size();
            BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: reset cleared sender dispatch queues"
                                       << ", frames = " << drained_call_keys.size()
                                       << ", totalResetDropped = " << reset_dropped_frames;
        }
    }

    /**
     * @brief Assigns a sender worker to a lane if it does not already have one.
     * @param lane_key Destination lane key.
     * @returns size_t Worker index.
     */
    size_t get_or_assign_sender_worker_for_lane(const std::string& lane_key) {
        if (sender_workers.empty()) {
            return 0U;
        }

        std::lock_guard<std::mutex> lock(sender_assignment_mutex);
        auto it = sender_lane_assignments.find(lane_key);
        if (it != sender_lane_assignments.end()) {
            return it->second;
        }

        size_t best_index = 0U;
        size_t best_count = sender_worker_lane_counts.empty() ? 0U : sender_worker_lane_counts[0];
        for (size_t i = 1; i < sender_worker_lane_counts.size(); i++) {
            if (sender_worker_lane_counts[i] < best_count) {
                best_count = sender_worker_lane_counts[i];
                best_index = i;
            }
        }

        sender_lane_assignments.emplace(lane_key, best_index);
        sender_worker_lane_counts[best_index]++;
        BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: assigned sender worker"
                                 << ", laneKey = " << lane_key
                                 << ", workerIndex = " << best_index;
        return best_index;
    }

    /**
     * @brief Enqueues a protocol frame into the sender worker assigned to its lane.
     * @param frame Outbound frame to dispatch.
     */
    void dispatch_protocol_frame(OutboundFrame frame) {
        const FrameLogInfo frame_info = make_frame_log_info(frame);
        if (sender_workers.empty()) {
            note_sender_dispatched(frame_info, 0U, 0U);
            if (send_protocol_frame(frame)) {
                release_dst_tgid_owner_for_sent_frame(frame);
            }
            return;
        }

        const std::string frame_call_key = frame.call_key;
        const std::string lane_key = frame.lane_key.empty() ? frame.call_key : frame.lane_key;
        const size_t index = get_or_assign_sender_worker_for_lane(lane_key);
        SenderWorkerState& worker_state = *sender_workers[index];
        std::string dropped_call_key;
        FrameLogInfo dropped_frame_info;
        bool dropped_from_worker_queue = false;
        size_t worker_depth = 0U;

        increment_pending_dispatch_for_call(frame_call_key);

        {
            std::lock_guard<std::mutex> lock(worker_state.mutex);
            if (worker_state.queue.size() >= sender_worker_max_queue_depth) {
                OutboundFrame dropped_frame = std::move(worker_state.queue.front());
                dropped_call_key = dropped_frame.call_key;
                dropped_frame_info = make_frame_log_info(dropped_frame);
                worker_state.queue.pop_front();
                dropped_frames++;
                dropped_from_worker_queue = true;
            }
            worker_state.queue.push_back(std::move(frame));
            worker_depth = worker_state.queue.size();
        }

        if (dropped_from_worker_queue) {
            decrement_pending_dispatch_for_call(dropped_call_key);
            note_frame_dropped(dropped_frame_info, "sender worker queue overflow");
        }

        note_sender_dispatched(frame_info, index, worker_depth);
        worker_state.cv.notify_one();
    }

    /**
     * @brief Worker loop that transmits protocol frames for one lane hash partition.
     * @param index Worker index.
     */
    void sender_worker_loop(size_t index) {
        SenderWorkerState& worker_state = *sender_workers[index];

        while (running.load()) {
            OutboundFrame frame;
            bool have_frame = false;

            {
                std::unique_lock<std::mutex> lock(worker_state.mutex);
                worker_state.cv.wait(lock, [&]() {
                    return worker_state.stop || !worker_state.queue.empty() || !running.load();
                });

                if ((worker_state.stop || !running.load()) && worker_state.queue.empty()) {
                    break;
                }

                if (!worker_state.queue.empty()) {
                    frame = std::move(worker_state.queue.front());
                    worker_state.queue.pop_front();
                    have_frame = true;
                }
            }

            if (have_frame) {
                if (send_protocol_frame(frame)) {
                    release_dst_tgid_owner_for_sent_frame(frame);
                }
                decrement_pending_dispatch_for_call(frame.call_key);
            }
        }
    }

    /**
     * @brief The main worker loop that handles receiving control packets, managing session timers, and sending 
     *  outbound frames.
     */
    void worker_loop() {
        while (running.load()) {
            const auto now = std::chrono::steady_clock::now();
            recv_control_packets();
            handle_session_timers();
            promote_stale_mux_lanes();
            reap_orphan_calls();

            if (net_state == NET_STAT_RUNNING) {
                int dispatches = 0;
                while (dispatches < 128) {
                    OutboundFrame frame;
                    if (!pop_ready_frame(frame, std::chrono::steady_clock::now())) {
                        break;
                    }

                    reserve_dispatch_pacing_slot(frame);
                    dispatch_protocol_frame(std::move(frame));
                    dispatches++;
                }

                if (dispatches == 0) {
                    log_running_queue_stall(now);
                }
            } else {
                log_queue_waiting_for_session(now);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    /**
     * @brief Handles session timers for login, authorization, configuration, and keepalive pings.
     *  This function checks the current session state and the next scheduled retry/ping time,
     *  and performs the appropriate action. While running, it sends PING keepalives and
     *  resets the session after too many consecutive missed PONG responses.
     */
    void handle_session_timers() {
        const auto now = std::chrono::steady_clock::now();

        if (net_state == NET_STAT_WAITING_CONNECT && now >= next_retry_at) {
            send_login();
            next_retry_at = now + std::chrono::milliseconds(fne_config.retryInterval);
            return;
        }

        if (net_state == NET_STAT_WAITING_LOGIN && now >= next_retry_at) {
            send_login();
            next_retry_at = now + std::chrono::milliseconds(fne_config.retryInterval);
            return;
        }

        if (net_state == NET_STAT_WAITING_AUTHORISATION && now >= next_retry_at) {
            send_authorisation();
            next_retry_at = now + std::chrono::milliseconds(fne_config.retryInterval);
            return;
        }

        if (net_state == NET_STAT_WAITING_CONFIG && now >= next_retry_at) {
            send_config();
            next_retry_at = now + std::chrono::milliseconds(fne_config.retryInterval);
            return;
        }

        if (net_state == NET_STAT_RUNNING && now >= next_ping_at) {
            if (awaiting_pong) {
                missed_ping_count++;
                if (missed_ping_count >= fne_config.maxMissedPings) {
                    BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: missed " << missed_ping_count
                                             << " consecutive PONG responses, resetting session";
                    reset_session();
                    return;
                }
            }

            send_ping();
            awaiting_pong = true;
            next_ping_at = now + std::chrono::milliseconds(FNE_PING_INTERVAL_MS);
        }
    }

    /**
     * @brief Receives control packets from the FNE server and processes them.
     *  This function continuously listens for incoming UDP packets on the socket. When a packet is received, it checks 
     *  for errors and validates the packet length. If the packet is valid, it calls handle_control_packet to process 
     * the packet based on its function and subfunction.
     */
    void recv_control_packets() {
        uint8_t buf[2048];
        udp::endpoint sender;

        while (running.load()) {
            boost::system::error_code ec;
            size_t n = socket.receive_from(boost::asio::buffer(buf, sizeof(buf)), sender, 0, ec);
            if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again) {
                return;
            }

            if (ec) {
                BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: receive error: " << ec.message();
                return;
            }

            if (n < RTP_FIXED_OVERHEAD) {
                continue;
            }

            handle_control_packet(buf, n);
        }
    }

    /**
     * @brief Handles a received control packet from the FNE server.
     *  This function checks the packet type and payload type to determine if it is a valid control packet. If valid, 
     *  it processes the packet based on its function (ACK, NAK, PING, PONG) and updates the session state accordingly. 
     *  It also handles the extraction of the salt for authorization and manages the sending of subsequent packets 
     *  (authorization, configuration, etc.)
     * @param packet Pointer to the received packet data.
     * @param n Size of the received packet in bytes.
     */
    void handle_control_packet(const uint8_t *packet, size_t n) {
        if (((packet[0U] >> 6) & 0x03U) != 0x02U) {
            return;
        }

        const uint8_t payload_type = (uint8_t)(packet[1U] & 0x7FU);
        if (payload_type != DVM_RTP_PAYLOAD_TYPE && payload_type != (uint8_t)(DVM_RTP_PAYLOAD_TYPE + 1U)) {
            return;
        }

        const uint8_t func = packet[18U];
        const uint8_t subfunc = packet[19U];
        (void)subfunc;

        const uint32_t msg_len = GET_UINT32(packet, 28U);
        if (RTP_FIXED_OVERHEAD + msg_len > n) {
            return;
        }

        const uint8_t *payload = packet + RTP_FIXED_OVERHEAD;

        if (func == NET_FUNC::ACK) {
            BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: received ACK from FNE"
                                    << ", state = " << net_state_name(net_state)
                                    << ", msgLen = " << msg_len;

            if (net_state == NET_STAT_WAITING_LOGIN) {
                if (msg_len >= 10U) {
                    std::memcpy(salt, payload + 6U, sizeof(salt));
                } else {
                    std::memset(salt, 0x00, sizeof(salt));
                }
                
                if (send_authorisation()) {
                    set_net_state(NET_STAT_WAITING_AUTHORISATION, "login ACK");
                    next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
                }
            } else if (net_state == NET_STAT_WAITING_AUTHORISATION) {
                if (send_config()) {
                    set_net_state(NET_STAT_WAITING_CONFIG, "authorisation ACK");
                    next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
                }
            } else if (net_state == NET_STAT_WAITING_CONFIG) {
                set_net_state(NET_STAT_RUNNING, "config ACK");
                awaiting_pong = false;
                missed_ping_count = 0U;
                next_ping_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(FNE_PING_INTERVAL_MS);
                BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: FNE session running";
            } else {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: unexpected ACK from FNE"
                                           << ", state = " << net_state_name(net_state)
                                           << ", msgLen = " << msg_len;
            }
            return;
        }

        if (func == NET_FUNC::NAK) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: received NAK from FNE, resetting session"
                                     << ", state = " << net_state_name(net_state)
                                     << ", msgLen = " << msg_len;
            reset_session();
            return;
        }

        if (func == NET_FUNC::PONG) {
            awaiting_pong = false;
            missed_ping_count = 0U;
            return;
        }
    }

    /**
     * @brief Sends a login packet to the FNE server to initiate the session.
     * @returns bool True when the packet was sent.
     */
    bool send_login() {
        std::vector<uint8_t> payload(8U, 0x00U);
        std::memcpy(payload.data(), TAG_REPEATER_LOGIN, 4U);
        SET_UINT32(fne_config.peerId, payload.data(), 4U);

        login_stream_id = random_stream_id();
        if (!send_enveloped(payload, NET_FUNC::RPTL, NET_SUBFUNC::NOP, next_seq(false), login_stream_id)) {
            return false;
        }

        set_net_state(NET_STAT_WAITING_LOGIN, "login sent");
        BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent login";
        return true;
    }

    /**
     * @brief Sends an authorization packet to the FNE server using the provided password and salt.
     * @returns bool True when the packet was sent.
     */
    bool send_authorisation() {
        std::vector<uint8_t> payload(40U, 0x00U);
        std::memcpy(payload.data(), TAG_REPEATER_AUTH, 4U);
        SET_UINT32(fne_config.peerId, payload.data(), 4U);

        std::vector<uint8_t> hash_input;
        hash_input.resize(sizeof(salt) + fne_config.password.size());
        std::memcpy(hash_input.data(), salt, sizeof(salt));
        std::memcpy(hash_input.data() + sizeof(salt), fne_config.password.data(), fne_config.password.size());

        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(hash_input.data(), hash_input.size(), digest);
        std::memcpy(payload.data() + 8U, digest, SHA256_DIGEST_LENGTH);

        if (!send_enveloped(payload, NET_FUNC::RPTK, NET_SUBFUNC::NOP, next_seq(false), login_stream_id)) {
            return false;
        }

        BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent auth";
        return true;
    }

    /**
     * @brief Sends a configuration packet to the FNE server with the current repeater settings.
     * @returns bool True when the packet was sent.
     */
    bool send_config() {
        json config = json::object();
        config["identity"] = fne_config.identity;
        config["rxFrequency"] = 0U;
        config["txFrequency"] = 0U;

        json info = json::object();
        info["latitude"] = 0.0F;
        info["longitude"] = 0.0F;
        info["height"] = 0U;
        info["location"] = "";
        config["info"] = info;

        json channel = json::object();
        channel["txPower"] = 0;
        channel["txOffsetMhz"] = 0.0F;
        channel["chBandwidthKhz"] = 0.0F;
        channel["channelId"] = 0U;
        channel["channelNo"] = 0U;
        config["channel"] = channel;

        json rcon = json::object();
        rcon["password"] = "";
        rcon["port"] = 0;
        config["rcon"] = rcon;

        config["peerClass"] = 2; // PEER_CONN_CLASS_STANDARD
        config["software"] = fne_config.software;

        const std::string cfg_json = config.dump();

        std::vector<uint8_t> payload(8U + cfg_json.size(), 0x00U);
        std::memcpy(payload.data(), TAG_REPEATER_CONFIG, 4U);
        std::memcpy(payload.data() + 8U, cfg_json.data(), cfg_json.size());

        if (!send_enveloped(payload, NET_FUNC::RPTC, NET_SUBFUNC::NOP, RTP_END_OF_CALL_SEQ, login_stream_id)) {
            return false;
        }

        BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent config";
        return true;
    }

    /**
     * @brief Sends a ping packet to the FNE server to maintain the session.
     */
    void send_ping() {
        std::vector<uint8_t> payload(1U, 0x00U);
        send_enveloped(payload, NET_FUNC::PING, NET_SUBFUNC::NOP, RTP_END_OF_CALL_SEQ, random_stream_id());
    }

    /**
     * @brief Sends a disconnect packet to the FNE server to terminate the session.
     */
    void send_disconnect() {
        if (net_state != NET_STAT_RUNNING) {
            return;
        }

        std::vector<uint8_t> payload(1U, 0x00U);
        send_enveloped(payload, NET_FUNC::RPT_DISC, NET_SUBFUNC::NOP, next_seq(false), random_stream_id());
    }

    /**
     * @brief Sends a protocol frame to the FNE server, managing stream state and sequence numbers.
     * @param frame The OutboundFrame containing the payload and call information.
     */
    bool send_protocol_frame(const OutboundFrame& frame) {
        uint32_t stream_id = 0U;
        uint32_t timestamp = 0U;
        uint16_t seq = 0U;
        const auto now = std::chrono::steady_clock::now();

        // scope is intentional
        {
            std::lock_guard<std::mutex> stream_lock(stream_state_mutex);
            StreamState* stream = nullptr;
            auto it = stream_state.find(frame.call_key);

            if (frame.end_of_call) {
                if (it == stream_state.end()) {
                    StreamState& created = stream_state[frame.call_key];
                    created.streamId = random_stream_id();
                    created.timestampInit = false;
                    created.next_protocol_send_at = now;
                    stream = &created;
                } else {
                    stream = &it->second;
                }
            } else {
                StreamState& created = stream_state[frame.call_key];
                if (created.streamId == 0U) {
                    created.streamId = random_stream_id();
                    created.timestampInit = false;
                    created.next_protocol_send_at = now;
                }
                stream = &created;
            }

            seq = next_seq(frame.end_of_call);

            const auto now_sys = std::chrono::system_clock::now();
            const uint32_t base_timestamp = (uint32_t)(std::chrono::duration_cast<std::chrono::milliseconds>(now_sys.time_since_epoch()).count() & 0xFFFFFFFFULL);
            if (!stream->timestampInit) {
                stream->timestampInit = true;
                stream->timestamp = base_timestamp;
            } else if (seq != RTP_END_OF_CALL_SEQ) {
                stream->timestamp += (uint32_t)(8000U / 133U);
            }

            timestamp = stream->timestamp;
            stream_id = stream->streamId;

            if (frame.end_of_call) {
                stream_state.erase(frame.call_key);
            }
        }

        if (frame.payload.size() >= MSG_HDR_SIZE &&
            std::memcmp(frame.payload.data(), TAG_P25_DATA, 4U) == 0) {
            uint32_t srcId = GET_UINT24(frame.payload.data(), 5U);
            uint32_t dstId = GET_UINT24(frame.payload.data(), 8U);
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: send_protocol_frame"
                                     << ", callKey = " << frame.call_key
                                     << ", streamId = " << stream_id
                                     << ", seq = " << seq
                                     << ", srcId = " << srcId
                                     << ", dstId = " << dstId
                                     << ", duid = " << (uint32_t)(frame.payload[22U])
                                     << ", frameLen = " << (uint32_t)(frame.payload[23U]);
        }

        const FrameLogInfo frame_info = make_frame_log_info(frame);
        note_protocol_send_attempt(frame_info, stream_id, seq, timestamp);

        return send_enveloped(frame.payload, NET_FUNC::PROTOCOL, NET_SUBFUNC::PROTOCOL_SUBFUNC_P25, seq, stream_id, timestamp, true);
    }

    /**
     * @brief Sends an enveloped RTP packet with the specified payload, function, subfunction, sequence number, and stream ID.
     * @param payload The payload data to send.
     * @param func The function code for the RTP packet.
     * @param subfunc The subfunction code for the RTP packet.
     * @param seq The sequence number for the RTP packet.
     * @param stream_id The stream ID for the RTP packet.
      * @param timestamp Optional RTP timestamp.
      * @param has_timestamp True when timestamp is provided by caller.
     */
    bool send_enveloped(const std::vector<uint8_t> &payload, uint8_t func, uint8_t subfunc, uint16_t seq,
          uint32_t stream_id, uint32_t timestamp = 0U, bool has_timestamp = false) {
        std::vector<uint8_t> packet(RTP_HEADER_LENGTH_BYTES + RTP_EXTENSION_HEADER_LENGTH_BYTES + RTP_FNE_HEADER_LENGTH_BYTES + payload.size(), 0x00U);

        packet[0U] = 0x90U; // RTP v2 + extension
        const uint8_t payload_type = (func == NET_FUNC::PROTOCOL) ? (uint8_t)(DVM_RTP_PAYLOAD_TYPE + 1U) : DVM_RTP_PAYLOAD_TYPE;
        packet[1U] = payload_type;
        SET_UINT16(seq, packet.data(), 2U);

        if (!has_timestamp) {
            const auto now = std::chrono::system_clock::now();
            timestamp = (uint32_t)(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() & 0xFFFFFFFFULL);
        }

        SET_UINT32(timestamp, packet.data(), 4U);
        SET_UINT32(fne_config.peerId, packet.data(), 8U);

        SET_UINT16(DVM_FRAME_START, packet.data(), 12U);
        SET_UINT16(RTP_FNE_HEADER_LENGTH_EXT_LEN, packet.data(), 14U);

        const uint16_t crc16 = CRC16_CCITT(payload.data(), payload.size() * 8U);
        SET_UINT16(crc16, packet.data(), 16U);

        packet[18U] = func;
        packet[19U] = subfunc;
        SET_UINT32(stream_id, packet.data(), 20U);
        SET_UINT32(fne_config.peerId, packet.data(), 24U);
        SET_UINT32((uint32_t)(payload.size()), packet.data(), 28U);

        std::memcpy(packet.data() + RTP_HEADER_LENGTH_BYTES + RTP_EXTENSION_HEADER_LENGTH_BYTES + RTP_FNE_HEADER_LENGTH_BYTES, payload.data(), payload.size());

        boost::system::error_code ec;

        // scope is intentional
        {
            std::lock_guard<std::mutex> socket_lock(socket_send_mutex);
            socket.send_to(boost::asio::buffer(packet.data(), packet.size()), remote_endpoint, 0, ec);
        }

        if (ec) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: send error: " << ec.message();
            reset_session();
            return false;
        }

        if (func == NET_FUNC::PROTOCOL) {
            if (payload.size() >= MSG_HDR_SIZE && std::memcmp(payload.data(), TAG_P25_DATA, 4U) == 0) {
                uint32_t srcId = GET_UINT24(payload.data(), 5U);
                uint32_t dstId = GET_UINT24(payload.data(), 8U);
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: P25 message header"
                                         << ", srcId = " << srcId
                                         << ", dstId = " << dstId
                                         << ", duid = " << (uint32_t)(payload[22U])
                                         << ", frameLen = " << (uint32_t)(payload[23U]);
            }

            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent protocol packet"
                                     << ", seq = " << seq
                                     << ", streamId = " << stream_id
                                     << ", payloadType = " << (uint32_t)(payload_type)
                                     << ", payloadBytes = " << payload.size();
        }

        return true;
    }

    /**
     * @brief Resets the session state, clearing stream and call states, and scheduling the next retry.
     */
    void reset_session() {
        std::lock_guard<std::mutex> reset_lock(reset_mutex);
        set_net_state(NET_STAT_WAITING_CONNECT, "reset_session");
        login_stream_id = 0;
        std::memset(salt, 0x00, sizeof(salt));

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(mux_mutex);
            tgid_call_key_to_call_key.clear();
            mux_lane_state.clear();
            call_mux_state.clear();
            mux_buffered_frames.clear();
        }

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            const size_t cleared_frames = queue_size;
            const size_t cleared_lanes = lane_queues.size();
            const size_t cleared_dst_owners = dst_tgid_active_calls.size();
            lane_queues.clear();
            lane_rr.clear();
            lane_in_rr.clear();
            pending_non_end_frames.clear();
            dst_tgid_active_calls.clear();
            dst_tgid_blocked_call_counts.clear();
            queue_size = 0U;

            if (cleared_frames > 0U || cleared_dst_owners > 0U) {
                reset_dropped_frames += cleared_frames;
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: reset cleared outbound queue"
                                           << ", frames = " << cleared_frames
                                           << ", lanes = " << cleared_lanes
                                           << ", dstOwners = " << cleared_dst_owners
                                           << ", totalResetDropped = " << reset_dropped_frames;
            }
        }

        // scope is intentional
        {
            std::lock_guard<std::mutex> stream_lock(stream_state_mutex);
            stream_state.clear();
        }

        clear_sender_dispatch_queues();

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            p25_call_state.clear();
        }

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(call_diagnostic_mutex);
            call_diagnostic_state.clear();
            invalid_source_drop_keys.clear();
        }

        next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
        next_ping_at = std::chrono::steady_clock::time_point{};
        next_queue_wait_log_at = std::chrono::steady_clock::time_point{};
        next_running_queue_stall_log_at = std::chrono::steady_clock::time_point{};
        last_queue_wait_state = NET_STAT_INVALID;
        last_queue_wait_size = 0U;
        awaiting_pong = false;
        missed_ping_count = 0U;
    }

private:
    struct SenderWorkerState {
        std::thread thread;
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<OutboundFrame> queue;
        bool stop = false;
    };

    FneConfig fne_config;
    std::vector<Route> routes;
    size_t max_queue_depth = 8192;

    boost::asio::io_context io;
    udp::socket socket;
    udp::endpoint remote_endpoint;

    std::atomic<bool> running{false};
    std::thread worker;

    std::unordered_map<std::string, std::deque<OutboundFrame>> lane_queues;
    std::deque<std::string> lane_rr;
    std::unordered_set<std::string> lane_in_rr;
    std::unordered_map<std::string, size_t> pending_non_end_frames;
    std::unordered_map<uint32_t, std::string> dst_tgid_active_calls;
    std::unordered_map<std::string, uint64_t> dst_tgid_blocked_call_counts;
    size_t queue_size = 0;
    std::mutex queue_mutex;

    std::unordered_map<std::string, StreamState> stream_state;
    mutable std::mutex stream_state_mutex;
    std::unordered_map<std::string, P25CallState> p25_call_state;
    std::mutex p25_state_mutex;

    std::vector<std::unique_ptr<SenderWorkerState>> sender_workers;
    std::vector<size_t> sender_worker_lane_counts;
    std::unordered_map<std::string, size_t> sender_lane_assignments;
    mutable std::mutex sender_assignment_mutex;
    size_t sender_worker_max_queue_depth = 4096;
    std::mutex socket_send_mutex;
    mutable std::mutex dispatch_accounting_mutex;
    std::unordered_map<std::string, size_t> pending_dispatched_frames;

    std::unordered_map<std::string, MuxLaneState> mux_lane_state;
    std::unordered_map<std::string, CallMuxState> call_mux_state;
    std::unordered_map<std::string, std::string> tgid_call_key_to_call_key;
    std::unordered_map<std::string, std::deque<OutboundFrame>> mux_buffered_frames;
    std::mutex mux_mutex;

    std::unordered_map<std::string, CallDiagnosticState> call_diagnostic_state;
    std::unordered_set<std::string> invalid_source_drop_keys;
    std::mutex call_diagnostic_mutex;

    NET_CONN_STATUS net_state = NET_STAT_INVALID;
    uint32_t login_stream_id = 0;
    uint16_t tx_seq = 0;
    std::mutex seq_mutex;
    std::mutex reset_mutex;
    uint8_t salt[4] = {0U, 0U, 0U, 0U};

    std::chrono::steady_clock::time_point next_retry_at{};
    std::chrono::steady_clock::time_point next_ping_at{};
    std::chrono::steady_clock::time_point next_queue_wait_log_at{};
    std::chrono::steady_clock::time_point next_running_queue_stall_log_at{};
    NET_CONN_STATUS last_queue_wait_state = NET_STAT_INVALID;
    size_t last_queue_wait_size = 0U;
    bool awaiting_pong = false;
    uint32_t missed_ping_count = 0U;

    uint64_t dropped_frames = 0;
    uint64_t dropped_mux_frames = 0;
    uint64_t dst_tgid_blocked_frames = 0;
    uint64_t dst_tgid_owner_priority_frames = 0;
    uint64_t dst_tgid_owner_releases = 0;
    uint64_t reset_dropped_frames = 0;
    uint64_t call_end_fallback_matches = 0;
    uint64_t queue_wait_logs = 0;
    uint64_t running_queue_stall_logs = 0;
    uint32_t mux_stale_call_ms = 1500;
    uint32_t mux_force_call_ms = 12000;

    std::mt19937 rng{std::random_device{}()};
    std::mutex rng_mutex;
};

BOOST_DLL_ALIAS(
    DVMTRP25Stream::create,       // <-- this function is exported with...
    create_plugin                 // <-- ...this alias name
)
