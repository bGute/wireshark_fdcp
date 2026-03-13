#include "config.h"
#include <epan/packet.h>
#include "ws_log_defs.h"

#define FDCP_PORT 2101

static const uint8_t SB = 0xF0;
static const uint8_t CB = 0xFF;
static const uint8_t ESCAPED_SB = 0x00;
static const uint8_t ESCAPED_CB = 0x01;

static int proto_fdcp;

static dissector_handle_t fdcp_handle;

static int hf_fdcp_pdu_type;
static const value_string packettypenames[] = {
    {0xDF, "BittnerReadAmpLoadImpedance"},
    {0xDD, "BittnerReadAmpStatus"},
    {0xDE, "BittnerReadAmpTemperature"},
    {0xC9, "BittnerSetStandby"},
    {0x0F, "DeviceSetNewAddress"},
    {0x19, "DeviceSystemReset"},
    {0x9B, "ExecuteRemoteCommand"},
    {0x0A, "GetAutoPowerSave"},
    {0x0A, "GetAmpGain"},
    {0x27, "GetAmplifierPreset"},
    {0x0A, "GetAmpPower"},
    {0x0A, "GetCardioidSwitch"},
    {0x0A, "GetCurrentAmplifierPreset"},
    {0x8E, "GetCurrentPresetName"},
    {0x22, "GetCurrentSpeakerPresetName"},
    {0x0A, "GetDelay"},
    {0x90, "GetDeviceAlias"},
    {0x20, "GetDeviceInfo"},
    {0x0A, "GetDisplayLight"},
    {0x0A, "GetDynamic"},
    {0x0A, "GetDynamicGain"},
    {0x0A, "GetDynamicTime"},
    {0x0A, "GetErrorConfig"},
    {0x0A, "GetFilter"},
    {0x0A, "GetGate"},
    {0x0A, "GetGateTime"},
    {0x0A, "GetInputConfiguration"},
    {0xA6, "GetIpConfig"},
    {0x0A, "GetLineFocusParameters"},
    {0x0A, "GetLink"},
    {0x0A, "GetLock"},
    {0x0A, "GetMono"},
    {0x94, "GetOutputChannelName"},
    {0x8E, "GetPresetName"},
    {0x1F, "GetRealDeviceInfo"},
    {0x0A, "GetRouting"},
    {0x0A, "GetSlaveSub"},
    {0x0A, "GetSpeakerPosition"},
    {0x22, "GetSpeakerPresetName"},
    {0x0A, "GetStackMate"},
    {0x0A, "GetStandby"},
    {0x0A, "GetSwitchConfiguration"},
    {0x0A, "GetVolume"},
    {0x0A, "GetXover"},
    {0x0A, "GetXperienceSubLevel"},
    {0x32, "LineReadback"},
    {0x23, "LoadAmplifierPreset"},
    {0x05, "LoadPreset"},
    {0x21, "LoadSpeakerPreset"},
    {0xAC, "PasswordLockControl"},
    {0x92, "PositionSensorControl"},
    {0x07, "ReadControls"},
    {0x04, "ReadEEProm"},
    {0x0B, "ReadOperatingTime"},
    {0xA0, "ReadPrecisionSignal"},
    {0x8D, "ReadSignals"},
    {0x0A, "ReadSpeakerPreset"},
    {0xA4, "ReadStatus"},
    {0x06, "SavePreset"},
    {0xAA, "SetAutoPowerSave"},
    {0x2A, "SetAmplifierPreset"},
    {0x24, "SetCardioidSwitch"},
    {0x86, "SetDelay"},
    {0x8F, "SetDeviceAlias"},
    {0x0D, "SetDisplayLight"},
    {0x83, "SetDynamic"},
    {0x84, "SetDynamicGain"},
    {0x85, "SetDynamicTime"},
    {0x09, "SetEEProm"},
    {0xA8, "SetErrorConfig"},
    {0x80, "SetFilter"},
    {0xA7, "SetFocusDelay"},
    {0x9D, "SetGainLine"},
    {0x89, "SetGate"},
    {0x8A, "SetGateTime"},
    {0x91, "SetGenerator"},
    {0x93, "SetGeneratorSwitch"},
    {0xAE, "SetInputConfiguration"},
    {0xA6, "SetIpConfig"},
    {0x9F, "SetLineFocusParameters"},
    {0xA2, "SetLink"},
    {0x10, "SetLock"},
    {0xA5, "SetMicChannel"},
    {0x24, "SetMono"},
    {0x96, "SetMute"},
    {0x95, "SetOutputChannelName"},
    {0x8C, "SetPresetName"},
    {0xA9, "SetReadStatus"},
    {0x9A, "SetRelais"},
    {0x81, "SetRouting"},
    {0x0E, "SetSlaveSub"},
    {0xA1, "SetSpeakerPosition"},
    {0xAD, "SetStackMate"},
    {0x0C, "SetStandby"},
    {0x99, "SetStepDelay"},
    {0x09, "SetStoreMode"},
    {0x9E, "SetSwitch"},
    {0xAB, "SetSwitchConfiguration"},
    {0x87, "SetVolume"},
    {0x96, "SetVolumeRelative"},
    {0x82, "SetXover"},
    {0x87, "SetXperienceSubLevel"},
    {0x26, "StartMeasure"},
    {0x03, "WriteEEProm"},
    {0x33, "WriteSpeakerPreset"}};
static int hf_fdcp_device_id;
static int hf_fdcp_data_count;
static int hf_fdcp_msb;
static int hf_fdcp_lsb;
static int hf_fdcp_data;
static int ett_fdcp;

static uint8_t decode_packet(uint8_t *encoded_buff, unsigned encoded_size, unsigned char *decoded_buffer, uint8_t decoded_buffer_len)
{
    uint8_t packet_malformed = 0;
    uint8_t d_idx = 0;
    for (unsigned i = 0; i < encoded_size; i += 1)
    {
        uint8_t curr = encoded_buff[i];
        if (curr == CB && i < encoded_size - 1)
        {
            uint8_t next = encoded_buff[i + 1];
            if (next == ESCAPED_SB)
            {
                curr = SB;
                // skip next value
                i += 1;
            }
            else if (next == ESCAPED_CB)
            {
                curr = CB;
                // skip next value
                i += 1;
            }
            else
            {
                // Malformed
                packet_malformed = 1;
                break;
            }
        }

        if (d_idx < decoded_buffer_len)
        {
            decoded_buffer[d_idx] = curr;
        }
        d_idx += 1;
    }

    return packet_malformed;
}

static void request_fdcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt)
{
    uint8_t packet_data_count = tvb_get_uint8(tvb, 2);

    proto_tree_add_item(pt, hf_fdcp_pdu_type, tvb, 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_fdcp_device_id, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_fdcp_data_count, tvb, 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_fdcp_msb, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_fdcp_lsb, tvb, 5, 1, ENC_BIG_ENDIAN);

    unsigned encoded_data_size = tvb_captured_length_remaining(tvb, 6);
    if (encoded_data_size != packet_data_count)
    {
        unsigned char *decoded_data_buffer = (unsigned char *)wmem_alloc(pinfo->pool, packet_data_count);
        uint8_t packet_malformed = decode_packet((uint8_t *)tvb_memdup(pinfo->pool, tvb, 6, encoded_data_size),
                                                 encoded_data_size, decoded_data_buffer, packet_data_count);
        if (packet_malformed == 0)
        {
            tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decoded_data_buffer, packet_data_count, packet_data_count);
            add_new_data_source(pinfo, next_tvb, "Decoded data");

            proto_tree_add_item(pt, hf_fdcp_data, next_tvb, 0, packet_data_count, ENC_BIG_ENDIAN);
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Malformed data");
        }
    }
    else
    {
        // No decoding needed
        proto_tree_add_item(pt, hf_fdcp_data, tvb, 6, packet_data_count, ENC_NA);
    }
}

static void response_fdcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt)
{
    unsigned packet_len = tvb_captured_length(tvb);
    proto_tree_add_item(pt, hf_fdcp_device_id, tvb, packet_len - 2, 1, ENC_BIG_ENDIAN);

    // Determine decoded packet size
    uint8_t packet_malformed = 0;
    unsigned packet_data_count = 0;
    for (unsigned i = 0; i < packet_len - 2; i += 1)
    {
        packet_data_count += 1;
        if (tvb_get_uint8(tvb, i) == CB)
        {
            if (i + 1 < packet_len - 2)
            {
                if (tvb_get_uint8(tvb, i + 1) == ESCAPED_SB || tvb_get_uint8(tvb, i + 1) == ESCAPED_CB)
                {
                    i += 1;
                }
                else
                {
                    packet_malformed = 1;
                    break;
                }
            }
            else
            {
                packet_malformed = 1;
                break;
            }
        }
    }

    if (packet_malformed == 1)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Malformed data");
        return;
    }

    if (packet_data_count == 0)
    {
        return;
    }

    if (packet_data_count != packet_len - 2)
    {
        // Decoding is needed
        unsigned char *decoded_data_buffer = (unsigned char *)wmem_alloc(pinfo->pool, packet_data_count);
        unsigned encoded_data_size = packet_len - 2;
        packet_malformed = decode_packet((uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, encoded_data_size),
                                         encoded_data_size, decoded_data_buffer, packet_data_count);
        if (packet_malformed == 0)
        {
            tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decoded_data_buffer, packet_data_count, packet_data_count);
            add_new_data_source(pinfo, next_tvb, "Decoded data");

            proto_tree_add_item(pt, hf_fdcp_data, next_tvb, 0, packet_data_count, ENC_NA);
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Malformed data");
        }
    }
    else
    {
        // No decoding needed
        proto_tree_add_item(pt, hf_fdcp_data, tvb, 0, packet_len - 2, ENC_NA);
    }
}

static int
dissect_fdcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    unsigned packet_len = tvb_captured_length(tvb);
    uint8_t packet_start_sb = tvb_get_uint8(tvb, 0);
    uint8_t packet_end_sb = tvb_get_uint8(tvb, packet_len - 1);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FDCP");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_fdcp, tvb, 0, -1, ENC_NA);
    proto_tree *fdcp_tree = proto_item_add_subtree(ti, ett_fdcp);

    if (packet_start_sb == SB)
    {
        uint8_t packet_type = tvb_get_uint8(tvb, 3);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Request %s",
                     val_to_str(pinfo->pool, packet_type, packettypenames, "Unknown (0x%02x)"));
        request_fdcp(tvb, pinfo, fdcp_tree);
    }
    else if (packet_end_sb == SB)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Response");
        response_fdcp(tvb, pinfo, fdcp_tree);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid package");
    }

    return tvb_captured_length(tvb);
}

void proto_register_fdcp(void)
{
    static hf_register_info hf[] = {
        {&hf_fdcp_pdu_type,
         {"Command", "fdcp.type",
          FT_UINT8, BASE_HEX,
          VALS(packettypenames), 0x0,
          NULL, HFILL}},
        {&hf_fdcp_device_id,
         {"Device ID", "fdcp.id",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_fdcp_data_count,
         {"Data count", "fdcp.dataCount",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_fdcp_msb,
         {"MSB", "fdcp.msb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_fdcp_lsb,
         {"LSB", "fdcp.lsb",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_fdcp_data,
         {"Data", "fdcp.data",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_fdcp};

    proto_fdcp = proto_register_protocol(
        "FDCP Protocol", /* protocol name        */
        "FDCP",          /* protocol short name  */
        "fdcp"           /* protocol filter_name */
    );

    proto_register_field_array(proto_fdcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fdcp_handle = register_dissector_with_description(
        "fdcp",          /* dissector name           */
        "FDCP Protocol", /* dissector description    */
        dissect_fdcp,    /* dissector function       */
        proto_fdcp       /* protocol being dissected */
    );
}

void proto_reg_handoff_fdcp(void)
{
    dissector_add_uint("udp.port", FDCP_PORT, fdcp_handle);
}