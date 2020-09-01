// Copyright (c) 2018, Smart Projects Holdings Ltd
// All rights reserved.
// See LICENSE file for license details.

// Payload protocol defines some structures for data exchange with
// onboard computer designed for custom payload project.

#ifndef _PAYLOAD_PROTOCOL_H_
#define _PAYLOAD_PROTOCOL_H_

#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>
#include <map>
#include <type_traits>
#include <algorithm>
#include <memory>

/** This value used to identify custom payload data from telemetry messages. */
#define CUSTOM_PAYLOAD_DATA_TYPE 0xAF

namespace Protocol {
namespace Modern {

using PayloadByteArray = std::vector<uint8_t>;

bool is_little_endian();

template<typename T, std::enable_if_t<std::is_class<T>::value, int> = 0>
void append(PayloadByteArray& array, const T& other) {
    array.insert(array.end(), other.begin(), other.end());
}

template<typename T, std::enable_if_t<std::is_integral<T>::value || std::is_enum<T>::value, int> = 0 >
void append(PayloadByteArray& array, const T& other) {
    auto begin = reinterpret_cast<const uint8_t*>(&other);
    auto end   = begin + sizeof(T);
    if (is_little_endian()) {
        std::copy(begin, end, std::back_inserter(array));
    } else {
        std::reverse_copy(begin, end, std::back_inserter(array));
    }
}

namespace Ucs {

enum class PayloadTypeId : uint8_t {
    Undefined = 0x00,
    Gpr = 0x01,
    Gpa = 0x02,
    GasAnalyzer = 0x05,
    Broadcast = 255
};

const uint8_t FORMAT = 0x01;

class DataMessage
{
public:
    DataMessage(PayloadTypeId payloadType, uint8_t format, PayloadByteArray message)
        : m_type(payloadType), m_format(format), m_message(move(message)) {

    }

    PayloadByteArray toByteArray() const {
        PayloadByteArray result;
        append(result, m_type);
        append(result, m_format);
        append(result, m_message);
        return result;
    }

private:
    PayloadTypeId m_type;
    uint8_t m_format;
    PayloadByteArray m_message;
};

class StatusMessage
{
public:
    enum class Status : uint8_t {
        Inactive = 0,
        Normal = 1,
        Warning = 2
    };

    StatusMessage(PayloadTypeId payloadType,
                  std::string name,
                  Status payloadStatus,
                  std::string statusString)
        : m_type(payloadType), m_name(name),
          m_status(payloadStatus), m_message(statusString) {
    }

    PayloadByteArray toByteArray() const {
        PayloadByteArray result;
        append(result, m_type);
        append(result, static_cast<uint8_t>(m_name.length()));
        append(result, m_name);
        append(result, m_status);
        append(result, m_message);
        return result;
    }

private:
    PayloadTypeId m_type;
    std::string m_name;
    Status m_status;
    std::string m_message;
};

class ValueMessage
{
private:
    enum class ValueType : uint8_t {
        INT32_TYPE = 2
    };
public:

    ValueMessage(int32_t value)
        : m_type(ValueType::INT32_TYPE), m_payload(static_cast<int>(sizeof(int32_t)), 0) {
        *reinterpret_cast<int32_t*>(m_payload.data()) = value;
    }

    PayloadByteArray toByteArray() const {
        PayloadByteArray result;
        append(result, m_type);
        append(result, m_payload);
        return result;
    }

private:
    ValueType m_type;
    PayloadByteArray m_payload;
};

}

namespace Payload {

enum class MessageId : uint8_t {
    PayloadStatus = 0x00,
    PayloadData = 0x01,
    PayloadValue = 0x02,

    PayloadCommand = 0x80,
};

class CompletePayload
{
public:
    CompletePayload(uint16_t m_identification, MessageId m_type,
                    uint8_t m_payloadId,
                    PayloadByteArray m_data)
        : m_identification(m_identification), m_type(m_type),
          m_payloadId(m_payloadId), m_data(m_data) {}

    uint16_t identification() const { return m_identification; }
    MessageId type() const { return m_type; }
    uint8_t payloadId() const { return m_payloadId; }
    const PayloadByteArray& data() const { return m_data; }

private:
    uint16_t m_identification;
    MessageId m_type;
    uint8_t m_payloadId;
    PayloadByteArray m_data;
};

struct PayloadMessageHeader
{
    uint16_t totalLength;
    uint16_t identification;
    uint16_t fragmentOffset;
    MessageId type;
    uint8_t payloadId;

    PayloadByteArray toByteArray() {
        PayloadByteArray result;
        append(result, totalLength);
        append(result, identification);
        append(result, fragmentOffset);
        append(result, type);
        append(result, payloadId);
        return result;
    }
} __attribute__((packed));

class PayloadMessage
{
public:
    PayloadMessage(const PayloadByteArray &data = PayloadByteArray());

    const PayloadMessageHeader& getHeader() const { return m_header; }
    const PayloadByteArray& getData() const { return m_data; }
    PayloadByteArray toByteArray();

    static std::vector<PayloadMessage> splitDataBlock(
            CompletePayload completePayload, size_t maxPayloadMessageSize);

private:
    PayloadMessage(PayloadMessageHeader header, const PayloadByteArray &fragment);

private:
    PayloadMessageHeader m_header;
    PayloadByteArray m_data;
};

}

namespace Onboard {

enum class MessageId : uint8_t {
    TelemetryMessage = 0x02,
    PongMessage = 0x04,

    CommandMessage = 0xFC,
    PingMessage = 0xFE
};

const uint8_t MAX_MESSAGE_SIZE = 100;

struct OnboardMessageHeader
{
    MessageId id;
    uint8_t length;

    static constexpr size_t size = sizeof(id) + sizeof(length);
} __attribute__((packed));

class OnboardMessage
{
public:
    OnboardMessage(MessageId id, uint8_t length);
    OnboardMessage(const PayloadByteArray &data);

    MessageId id() const { return m_header.id; }
    uint8_t length() const { return m_header.length; }
    const uint8_t *payload() const { return m_payload.data(); }
    uint16_t crc() const { return m_crc; }

    uint16_t computeCrc() const;
    void updateCrc();
    PayloadByteArray toByteArray();

    bool isValid() const { return m_valid && computeCrc() == m_crc; }

    void copyToPayload(const void *payload) {
        auto begin = reinterpret_cast<const uint8_t*>(payload);
        m_payload.assign(begin, begin + m_header.length);
        updateCrc();
    }

    static constexpr uint8_t ExtraSize = static_cast<uint8_t>(sizeof(OnboardMessageHeader) + sizeof(uint16_t/*m_crc*/));

private:
    static void updateCrc(uint16_t &crc, const void *buffer, size_t length);

private:
    OnboardMessageHeader m_header;
    PayloadByteArray m_payload;
    uint16_t m_crc;

    static uint16_t m_counter;
    bool m_valid = true;
};


//
// Ping/Pong Message
//

struct PingPayload {
    int64_t timeStampMs;
} __attribute__((packed));

struct PongMessage {
    uint64_t timestamp;
} __attribute__((packed));

}

namespace Logic {

class MessageDispatcher {
public:
    template<typename PingPongHandler, typename TelemetryCommandHandler>
    void handle(const Onboard::OnboardMessage& message,
                PingPongHandler pongHandler,
                TelemetryCommandHandler telemetryHandler) {
        if (!message.isValid())
            return;

        switch (message.id()) {
        case Onboard::MessageId::TelemetryMessage:
        case Onboard::MessageId::CommandMessage:
        {
            auto begin = message.payload();
            Payload::PayloadMessage payloadMessage(PayloadByteArray(begin, begin + message.length()));
            auto completePayloadOpt = putMessage(payloadMessage);
            if (completePayloadOpt) {
                telemetryHandler(message.id(), *completePayloadOpt);
            }
            break;
        }
        case Onboard::MessageId::PongMessage:
        case Onboard::MessageId::PingMessage:
            pongHandler(message.id(), *reinterpret_cast<const uint64_t*>(message.payload()));
            break;
        }
    }

    Payload::CompletePayload createCompletePayload(Payload::MessageId type,
        uint8_t payloadId, const PayloadByteArray& data) {
        return Payload::CompletePayload(identification++, type, payloadId, data);
    }

    std::vector<PayloadByteArray> prepareDataForSend(const Payload::CompletePayload& completeMessage, Onboard::MessageId messageId) {
        std::vector<PayloadByteArray> result;
        const size_t MAX_SIZE = Onboard::MAX_MESSAGE_SIZE - Onboard::OnboardMessage::ExtraSize;
        auto messages = Payload::PayloadMessage::splitDataBlock(completeMessage, MAX_SIZE);
        for (auto &message : messages) {
            PayloadByteArray messageBytes = message.toByteArray();
            Onboard::OnboardMessage onboard(messageId, static_cast<uint8_t>(messageBytes.size()));
            onboard.copyToPayload(messageBytes.data());
            result.push_back(onboard.toByteArray());
        }
        return result;
    }

private:
    class PayloadMessageGroup {
    public:
        PayloadMessageGroup() : currentLength(0), header() {}

        PayloadMessageGroup(const Payload::PayloadMessage& message) : currentLength(0), header(message.getHeader()) {
            add(message);
        }

        bool add(const Payload::PayloadMessage& message) {
            auto &messageHeader = message.getHeader();
            if (messageHeader.identification == header.identification
                    && messageHeader.totalLength == header.totalLength
                    && messageHeader.type == header.type
                    && messageHeader.payloadId == header.payloadId
                    && message.getData().size() <= header.totalLength - currentLength
                    && !offsets.count(messageHeader.fragmentOffset)) {
                offsets[messageHeader.fragmentOffset] = message.getData();
                currentLength += message.getData().size();
                return true;
            }
            return false;
        }

        std::unique_ptr<Payload::CompletePayload> tryGetCompletePayload() {
            if (currentLength != header.totalLength)
                return nullptr;

            PayloadByteArray data;
            data.reserve(header.totalLength);
            for (auto &offset_it : offsets) {
                auto &offset = offset_it.first;
                auto &payload = offset_it.second;
                if (data.size() != offset)
                    return nullptr;
                append(data, payload);
            }

            if (data.size() == header.totalLength) {
                auto id = header.identification;
                auto type = header.type;
                auto payloadId = header.payloadId;
                return std::make_unique<Payload::CompletePayload>(id, type,payloadId, data);
            }
            return nullptr;
        }
    private:
        std::map<uint16_t, PayloadByteArray> offsets;
        size_t currentLength;
        Payload::PayloadMessageHeader header;
    };

    std::unique_ptr<Payload::CompletePayload> putMessage(const Payload::PayloadMessage& message) {
        auto identification = message.getHeader().identification;
        {
            auto it = messageMap.find(identification);
            if (it != messageMap.end()) {
                bool success = it->second.add(message);
                if (!success) {
                    messageMap.erase(it);
                }
            } else {
                while (messageMap.size() >= MAX_MESSAGE_MAP_SIZE) {
                    messageMap.erase(messageMap.begin());
                }
                messageMap.insert(std::make_pair(identification,PayloadMessageGroup(message)));
            }
        }
        auto it = messageMap.find(identification);
        auto resultOpt = it->second.tryGetCompletePayload();
        if (resultOpt) {
            messageMap.erase(it);
        }
        return resultOpt;
    }

    static constexpr size_t MAX_MESSAGE_MAP_SIZE = 20;
    std::unordered_map<uint16_t, PayloadMessageGroup> messageMap;
    uint16_t identification = 0;
};

/*
 * base64 snippet from
 * https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
 *
 */

#include <vector>
#include <string>
typedef unsigned char BYTE;

std::string base64_encode(BYTE const* buf, unsigned int bufLen);
std::vector<BYTE> base64_decode(std::string const&);

}

}
}

#endif /* _PAYLOAD_PROTOCOL_H_ */
