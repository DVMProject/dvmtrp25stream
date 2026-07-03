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
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
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
 * @param short_name The short name associated with the call.
 * @param call_num The call number.
 * @returns std::string A unique call key in the format "short_name:call_num".
 */
std::string make_call_key(const std::string& short_name, long call_num) 
{
    std::ostringstream oss;
    oss << short_name << ":" << call_num;
    return oss.str();
}

/**
 * @brief Generates a unique mux lane key based on the short name and destination TGID.
 * @param short_name The short name associated with the mux lane.
 * @param dst_tgid The destination TGID.
 * @returns std::string A unique mux lane key in the format "short_name:dst_tgid".
 */
std::string make_mux_lane_key(const std::string &short_name, uint32_t dst_tgid) 
{
    std::ostringstream oss;
    oss << short_name << ":" << dst_tgid;
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
    bool debug = false;
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
    std::vector<uint8_t> payload;
    bool end_of_call = false;
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
    bool active = false;
    bool queued = false;
    bool ended = false;
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
        if (fne_config.maxMissedPings == 0U) {
            fne_config.maxMissedPings = 10U;
        }
        fne_config.debug = fne.value("debug", false);

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
                                 << ", maxMissedPings = " << fne_config.maxMissedPings;

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
            net_state = NET_STAT_WAITING_CONNECT;
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
        const std::string call_key = make_call_key(call_info.short_name, call_info.call_num);
        const Route *route = find_route(call_info.talkgroup, call_info.short_name, call_info.encrypted);

        P25CallState state;
        bool have_state = false;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            auto it = p25_call_state.find(call_key);
            if (it != p25_call_state.end()) {
                state = it->second;
                p25_call_state.erase(it);
                have_state = true;
            }
        }

        const uint32_t dst_tgid = resolve_dst_tgid(route, call_info.talkgroup);
        const std::string fallback_lane_key = make_mux_lane_key(call_info.short_name, dst_tgid);
        const std::string lane_key = resolve_lane_key_for_call(call_key, fallback_lane_key);

        if (!route && !have_state && !has_mux_call_state(call_key)) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: call_end no route/state, callKey = " << call_key
                                         << ", tgid = " << call_info.talkgroup
                                         << ", shortName = " << call_info.short_name;
            }
            return 0;
        }

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
            header.srcId = call_info.source_num & 0x00FFFFFFU;
            header.dstId = dst_tgid;
            header.sysId = static_cast<uint16_t>(call_info.sys_num & 0xFFFFU);
            header.serviceOptions = call_info.encrypted ? 0x40U : 0x00U;
        }

        queue_silence_ldu_pair(lane_key, call_key, header, call_info.encrypted, have_state ? state.nextIsLDU2 : false);

        OutboundFrame frame;
        frame.call_key = call_key;
        frame.payload = build_tdu_payload(header);
        frame.end_of_call = true;
        schedule_mux_frame(lane_key, call_key, std::move(frame));
        mark_mux_call_ended(call_key, lane_key);

        if (fne_config.debug) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: queued TDU, callKey = " << call_key
                                     << ", dstTg = " << header.dstId;
        }
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
        (void)errs;
        if (!call || !params || param_count <= 0) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame (invalid callback args)";
            }
            return 0;
        }

        if (codec_type != 0 || param_count < 8) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame, codecType = " << codec_type
                                         << ", paramCount = " << param_count;
            }
            return 0;
        }

        System *system = call->get_system();
        if (!system) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: skipping voice frame (missing system pointer)";
            }
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
            }
        }

        if (route == nullptr && callback_tgid > 0) {
            route = find_route(callback_tgid, short_name, encrypted);
            if (route != nullptr) {
                actual_tgid = callback_tgid;
            }
        }

        if (!route) {
            return 0;
        } else {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: valid route for, tgid = " << actual_tgid
                                         << ", shortName = " << short_name
                                         << ", encrypted = " << encrypted;
            }
        }

        const uint32_t dst_tgid = resolve_dst_tgid(route, actual_tgid);
        const std::string lane_key = make_mux_lane_key(short_name, dst_tgid);

        const long current_src = call->get_current_source_id();
        uint32_t effective_src = 0U;
        if (current_src > 0 && current_src <= 0x00FFFFFFL) {
            effective_src = (uint32_t)(current_src);
        } else if (src_id > 0 && src_id <= 0x00FFFFFFU) {
            effective_src = src_id;
        }

        if (effective_src == 0U) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: dropping voice frame with invalid source ID"
                                         << ", callSrc = " << current_src
                                         << ", cbSrc = " << src_id
                                         << ", callTg = " << call_tgid
                                         << ", cbTg = " << callback_tgid;
            }
            return 0;
        }

        std::array<uint8_t, RAW_IMBE_LENGTH_BYTES> imbe{};
        if (!pack_imbe(params, param_count, imbe)) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: failed IMBE pack for tgid=" << actual_tgid;
            }
            return 0;
        }

        const std::string call_key = make_call_key(short_name, call->get_call_num());

        P25CallState ready_state;
        bool emit_ldu = false;
        bool emit_ldu2 = false;
        bool queue_leading_silence = false;
        P25MessageHdr leading_header;

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            P25CallState& state = p25_call_state[call_key];
            state.header = build_message_header(call, system, effective_src, actual_tgid, route);

            const uint32_t normalized_src = effective_src & 0x00FFFFFFU;
            const uint32_t normalized_dst = dst_tgid & 0x00FFFFFFU;
            if (fne_config.debug &&
                (state.header.srcId != normalized_src || state.header.dstId != normalized_dst)) {
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

        if (queue_leading_silence) {
            queue_silence_ldu_pair(lane_key, call_key, leading_header, encrypted, false);
        }

        if (emit_ldu) {
            OutboundFrame frame;
            frame.call_key = call_key;
            frame.end_of_call = false;
            frame.payload = build_ldu_payload(ready_state, emit_ldu2);

            if (fne_config.debug && frame.payload.size() >= MSG_HDR_SIZE &&
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

            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: queued " << (emit_ldu2 ? "LDU2" : "LDU1")
                                         << ", callKey = " << call_key
                                         << ", srcTg = " << actual_tgid
                                         << ", dstTg = " << dst_tgid;
            }
        }

        return 0;
    }

private:
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
            call_mux_state.erase(finished_call_key);
            mux_buffered_frames.erase(finished_call_key);
            return;
        }

        MuxLaneState& lane = lane_it->second;
        if (lane.active_call_key == finished_call_key) {
            lane.active_call_key.clear();
        }

        call_mux_state.erase(finished_call_key);
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
            lane.active_call_key = next_call_key;

            flush_mux_buffered_frames_locked(next_call_key);

            if (!next_it->second.ended) {
                break;
            }

            lane.active_call_key.clear();
            call_mux_state.erase(next_it);
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

        CallMuxState& call_state = call_mux_state[call_key];
        call_state.lane_key = lane_key;

        MuxLaneState& lane = mux_lane_state[lane_key];

        if (lane.active_call_key.empty()) {
            lane.active_call_key = call_key;
            call_state.active = true;
            call_state.queued = false;
        }

        if (lane.active_call_key == call_key) {
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
                continue;
            }

            const bool ended = call_it->second.ended;
            const auto threshold = ended ? stale_after : force_after;
            if (now - last > threshold) {
                stale_lanes.emplace_back(lane_key, lane.active_call_key);
            }
        }

        for (const auto& stale : stale_lanes) {
            if (fne_config.debug) {
                BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: promoting stale mux active call"
                                         << ", lane = " << stale.first
                                         << ", callKey = " << stale.second
                                         << ", waiting = " << mux_lane_state[stale.first].waiting_calls.size();
            }
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

        header.netId = (uint32_t)(system->get_wacn() & 0x00FFFFFFUL);

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
        if (queue.size() >= max_queue_depth) {
            queue.pop_front();
            dropped_frames++;
            if ((dropped_frames % 100U) == 0U) {
                BOOST_LOG_TRIVIAL(warning) << "dvmtrp25stream: queue overflow, dropped frames=" << dropped_frames;
            }
        }

        queue.push_back(std::move(frame));
    }

    /**
     * @brief Requeues an outbound frame at the front to retry later.
     * @param frame The OutboundFrame to requeue.
     */
    void requeue_frame_front(OutboundFrame frame) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        if (queue.size() >= max_queue_depth) {
            queue.pop_back();
            dropped_frames++;
        }

        queue.push_front(std::move(frame));
    }

    /**
     * @brief Checks whether queued non-end frames still exist for a call.
     * @param call_key Per-call key.
     * @returns bool True when unsent non-end frames remain in the outbound queue.
     */
    bool has_pending_non_end_frames_for_call(const std::string& call_key) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        for (const auto& frame : queue) {
            if (frame.call_key == call_key && !frame.end_of_call) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Pops an outbound frame from the queue for transmission.
     * @param out Reference to the OutboundFrame where the popped frame will be stored.
     * @returns bool True if a frame was successfully popped, false if the queue was empty
     */
    bool pop_frame(OutboundFrame& out) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        if (queue.empty()) {
            return false;
        }
        
        out = std::move(queue.front());
        queue.pop_front();
        return true;
    }

    /**
     * @brief Generates a random stream ID for the session.
     * @returns uint32_t A random stream ID in the range [1, 0xFFFFFFFE].
     */
    uint32_t random_stream_id() {
        std::uniform_int_distribution<uint32_t> dist(1U, 0xFFFFFFFEU);
        return dist(rng);
    }

    /**
     * @brief Generates the next sequence number for RTP packets, wrapping around at RTP_END_OF_CALL_SEQ.
     * @param end_of_call Boolean indicating whether this is the end of a call.
     * @returns uint16_t The next sequence number.
     */
    uint16_t next_seq(bool end_of_call = false) {
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
     * @brief The main worker loop that handles receiving control packets, managing session timers, and sending 
     *  outbound frames.
     */
    void worker_loop() {
        while (running.load()) {
            recv_control_packets();
            handle_session_timers();
            promote_stale_mux_lanes();

            if (net_state == NET_STAT_RUNNING) {
                OutboundFrame frame;
                int sends = 0;
                while (sends < 64 && pop_frame(frame)) {
                    if (!send_protocol_frame(frame)) {
                        requeue_frame_front(std::move(frame));
                        break;
                    }
                    sends++;
                }
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
            if (net_state == NET_STAT_WAITING_LOGIN) {
                if (msg_len >= 10U) {
                    std::memcpy(salt, payload + 6U, sizeof(salt));
                } else {
                    std::memset(salt, 0x00, sizeof(salt));
                }
                
                send_authorisation();
                net_state = NET_STAT_WAITING_AUTHORISATION;
                next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
            } else if (net_state == NET_STAT_WAITING_AUTHORISATION) {
                send_config();
                net_state = NET_STAT_WAITING_CONFIG;
                next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
            } else if (net_state == NET_STAT_WAITING_CONFIG) {
                net_state = NET_STAT_RUNNING;
                awaiting_pong = false;
                missed_ping_count = 0U;
                next_ping_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(FNE_PING_INTERVAL_MS);
                BOOST_LOG_TRIVIAL(info) << "dvmtrp25stream: FNE session running";
            }
            return;
        }

        if (func == NET_FUNC::NAK) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: received NAK from FNE, resetting session";
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
     */
    void send_login() {
        std::vector<uint8_t> payload(8U, 0x00U);
        std::memcpy(payload.data(), TAG_REPEATER_LOGIN, 4U);
        SET_UINT32(fne_config.peerId, payload.data(), 4U);

        login_stream_id = random_stream_id();
        send_enveloped(payload, NET_FUNC::RPTL, NET_SUBFUNC::NOP, next_seq(false), login_stream_id);

        net_state = NET_STAT_WAITING_LOGIN;
        if (fne_config.debug) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent login";
        }
    }

    /**
     * @brief Sends an authorization packet to the FNE server using the provided password and salt.
     */
    void send_authorisation() {
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

        send_enveloped(payload, NET_FUNC::RPTK, NET_SUBFUNC::NOP, next_seq(false), login_stream_id);
        if (fne_config.debug) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent auth";
        }
    }

    /**
     * @brief Sends a configuration packet to the FNE server with the current repeater settings.
     */
    void send_config() {
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

        send_enveloped(payload, NET_FUNC::RPTC, NET_SUBFUNC::NOP, RTP_END_OF_CALL_SEQ, login_stream_id);
        if (fne_config.debug) {
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: sent config";
        }
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
        StreamState *stream = nullptr;
        auto it = stream_state.find(frame.call_key);
        const auto now = std::chrono::steady_clock::now();

        if (frame.end_of_call) {
            // preserve per-call ordering: never let the TDU overtake queued
            // voice/silence LDUs for the same call
            if (has_pending_non_end_frames_for_call(frame.call_key)) {
                return false;
            }

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

            // LDU frames represent ~180 ms of audio; pacing avoids burst sends
            // that destabilize voice continuity at the receiver
            if (stream->next_protocol_send_at.time_since_epoch().count() != 0 &&
                now < stream->next_protocol_send_at) {
                return false;
            }
        }

        const uint16_t seq = next_seq(frame.end_of_call);

        if (fne_config.debug && frame.payload.size() >= MSG_HDR_SIZE &&
            std::memcmp(frame.payload.data(), TAG_P25_DATA, 4U) == 0) {
            uint32_t srcId = GET_UINT24(frame.payload.data(), 5U);
            uint32_t dstId = GET_UINT24(frame.payload.data(), 8U);
            BOOST_LOG_TRIVIAL(debug) << "dvmtrp25stream: send_protocol_frame"
                                     << ", callKey = " << frame.call_key
                                     << ", streamId = " << stream->streamId
                                     << ", seq = " << seq
                                     << ", srcId = " << srcId
                                     << ", dstId = " << dstId
                                     << ", duid = " << (uint32_t)(frame.payload[22U])
                                     << ", frameLen = " << (uint32_t)(frame.payload[23U]);
        }

        send_enveloped(frame.payload, NET_FUNC::PROTOCOL, NET_SUBFUNC::PROTOCOL_SUBFUNC_P25, seq, stream->streamId, stream);

        if (!frame.end_of_call) {
            stream->next_protocol_send_at = now + std::chrono::milliseconds(160);
        }

        if (frame.end_of_call) {
            stream_state.erase(frame.call_key);
        }

        return true;
    }

    /**
     * @brief Sends an enveloped RTP packet with the specified payload, function, subfunction, sequence number, and stream ID.
     * @param payload The payload data to send.
     * @param func The function code for the RTP packet.
     * @param subfunc The subfunction code for the RTP packet.
     * @param seq The sequence number for the RTP packet.
     * @param stream_id The stream ID for the RTP packet.
     * @param stream_state Optional pointer to the StreamState for managing timestamps.
     */
    void send_enveloped(const std::vector<uint8_t> &payload, uint8_t func, uint8_t subfunc, uint16_t seq,
        uint32_t stream_id, StreamState *stream_state = nullptr) {
        std::vector<uint8_t> packet(RTP_HEADER_LENGTH_BYTES + RTP_EXTENSION_HEADER_LENGTH_BYTES + RTP_FNE_HEADER_LENGTH_BYTES + payload.size(), 0x00U);

        packet[0U] = 0x90U; // RTP v2 + extension
        const uint8_t payload_type = (func == NET_FUNC::PROTOCOL) ? (uint8_t)(DVM_RTP_PAYLOAD_TYPE + 1U) : DVM_RTP_PAYLOAD_TYPE;
        packet[1U] = payload_type;
        SET_UINT16(seq, packet.data(), 2U);

        const auto now = std::chrono::system_clock::now();
        uint32_t timestamp = (uint32_t)(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() & 0xFFFFFFFFULL);
        if (stream_state != nullptr) {
            if (!stream_state->timestampInit) {
                stream_state->timestampInit = true;
                stream_state->timestamp = timestamp;
            } else if (seq != RTP_END_OF_CALL_SEQ) {
                stream_state->timestamp += (uint32_t)(8000U / 133U);
            }
            timestamp = stream_state->timestamp;
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
        socket.send_to(boost::asio::buffer(packet.data(), packet.size()), remote_endpoint, 0, ec);
        if (ec) {
            BOOST_LOG_TRIVIAL(error) << "dvmtrp25stream: send error: " << ec.message();
            reset_session();
            return;
        }

        if (fne_config.debug && func == NET_FUNC::PROTOCOL) {
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
    }

    /**
     * @brief Resets the session state, clearing stream and call states, and scheduling the next retry.
     */
    void reset_session() {
        net_state = NET_STAT_WAITING_CONNECT;
        login_stream_id = 0;
        std::memset(salt, 0x00, sizeof(salt));
        stream_state.clear();

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(mux_mutex);
            mux_lane_state.clear();
            call_mux_state.clear();
            mux_buffered_frames.clear();
        }

        // scope is intentional
        {
            std::lock_guard<std::mutex> lock(p25_state_mutex);
            p25_call_state.clear();
        }

        next_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(fne_config.retryInterval);
        next_ping_at = std::chrono::steady_clock::time_point{};
        awaiting_pong = false;
        missed_ping_count = 0U;
    }

private:
    FneConfig fne_config;
    std::vector<Route> routes;
    size_t max_queue_depth = 8192;

    boost::asio::io_context io;
    udp::socket socket;
    udp::endpoint remote_endpoint;

    std::atomic<bool> running{false};
    std::thread worker;

    std::deque<OutboundFrame> queue;
    std::mutex queue_mutex;

    std::unordered_map<std::string, StreamState> stream_state;
    std::unordered_map<std::string, P25CallState> p25_call_state;
    std::mutex p25_state_mutex;

    std::unordered_map<std::string, MuxLaneState> mux_lane_state;
    std::unordered_map<std::string, CallMuxState> call_mux_state;
    std::unordered_map<std::string, std::deque<OutboundFrame>> mux_buffered_frames;
    std::mutex mux_mutex;

    NET_CONN_STATUS net_state = NET_STAT_INVALID;
    uint32_t login_stream_id = 0;
    uint16_t tx_seq = 0;
    uint8_t salt[4] = {0U, 0U, 0U, 0U};

    std::chrono::steady_clock::time_point next_retry_at{};
    std::chrono::steady_clock::time_point next_ping_at{};
    bool awaiting_pong = false;
    uint32_t missed_ping_count = 0U;

    uint64_t dropped_frames = 0;
    uint64_t dropped_mux_frames = 0;
    uint32_t mux_stale_call_ms = 1500;
    uint32_t mux_force_call_ms = 12000;

    std::mt19937 rng{std::random_device{}()};
};

BOOST_DLL_ALIAS(
    DVMTRP25Stream::create,       // <-- this function is exported with...
    create_plugin                 // <-- ...this alias name
)
