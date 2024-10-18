%%% +----------------------------------------------------------------+
%%% | Copyright (c) 2024. Tokenov Alikhan, alikhantokenov@gmail.com  |
%%% | All rights reserved.                                           |
%%% | License that can be found in the LICENSE file.                 |
%%% +----------------------------------------------------------------+

-ifndef(ft12_sniffer).
-define(ft12_sniffer, 1).

-include_lib("kernel/include/logger.hrl").

-define(SELF, pid_to_list(self()) ++ ": ").
-define(LOGERROR(Text),           ?LOG_ERROR(?SELF ++ Text)).
-define(LOGERROR(Text, Params),   ?LOG_ERROR(?SELF ++ Text, Params)).
-define(LOGWARNING(Text),         ?LOG_WARNING(?SELF ++ Text)).
-define(LOGWARNING(Text, Params), ?LOG_WARNING(?SELF ++ Text, Params)).
-define(LOGINFO(Text),            ?LOG_INFO(?SELF ++ Text), io:format(?SELF ++ Text ++ "~n")).
-define(LOGINFO(Text, Params),    ?LOG_INFO(?SELF ++ Text, Params), io:format(?SELF ++ Text ++ "~n", Params)).
-define(LOGDEBUG(Text),           ?LOG_DEBUG(?SELF ++ Text)).
-define(LOGDEBUG(Text, Params),   ?LOG_DEBUG(?SELF ++ Text, Params)).

-define(ENV(Key, Default), application:get_env(ft12_sniffer, Key, Default)).
-define(ENV(OS, Config, Default),
  (fun() ->
    case os:getenv(OS) of
      false -> ?ENV(Config,Default);
      Value -> Value
    end
   end)()
).

%% Physical transmission direction
-define(FROM_A_TO_B, 1).
-define(FROM_B_TO_A, 0).

-record(control_field_request, {
  direction,
  fcb,
  fcv,
  function_code
}).

-record(control_field_response, {
  direction,
  acd,
  dfc,
  function_code
}).

-record(frame, {
  address,
  control_field,
  data
}).

-record(asdu, {
  type,
  t = 0,
  pn,
  cot,
  org,
  coa,
  objects
}).

-define(DEFAULT_ASDU_SETTINGS,#{
  coa => 1,
  org => 0,
  coa_size => 2,
  org_size => 1,
  ioa_size => 3
}).

-define(POSITIVE_PN, 0).
-define(NEGATIVE_PN, 1).

%% Cause of transmission (COT) values
-define(COT_PER, 1).
-define(COT_BACK, 2).
-define(COT_SPONT, 3).
-define(COT_INIT, 4).
-define(COT_REQ, 5).
-define(COT_ACT, 6).
-define(COT_ACTCON, 7).
-define(COT_DEACT, 8).
-define(COT_DEACTCON, 9).
-define(COT_ACTTERM, 10).
-define(COT_RETREM, 11).
-define(COT_RETLOC, 12).
-define(COT_FILE, 13).
-define(COT_GROUP_MIN, 20).
-define(COT_GROUP_MAX, 36).
-define(COT_GROUP_COUNTER_MIN, 37).
-define(COT_GROUP(ID), ?COT_GROUP_MIN + ID).
-define(COT_GROUP_COUNTER_MAX, 41).
-define(COT_UNKNOWN_TYPE, 44).
-define(COT_UNKNOWN_CAUSE, 45).
-define(COT_UNKNOWN_ASDU_ADDRESS, 46).
-define(COT_UNKNOWN_OBJECT_ADDRESS, 47).
%% Structure Qualifier (SQ) types:
%% 0 - Different IOAs
%% 1 - Continuous IOAs
-define(SQ_0, 16#00:1).
-define(SQ_1, 16#01:1).

%% Monitor direction types
-define(M_SP_NA_1, 16#01). %  1: SIQ                                     | Single point information
-define(M_SP_TA_1, 16#02). %  2: SIQ + CP24Time2A                        | Single point information with time tag
-define(M_DP_NA_1, 16#03). %  3: DIQ                                     | Double point information
-define(M_DP_TA_1, 16#04). %  4: DIQ + CP24Time2A                        | Double point information with time tag
-define(M_ST_NA_1, 16#05). %  5: VTI + QDS                               | Step position information
-define(M_ST_TA_1, 16#06). %  6: VTI + QDS + CP24Time2A                  | Step position information with time tag
-define(M_BO_NA_1, 16#07). %  7: BSI + QDS                               | Bit string of 32 bit
-define(M_BO_TA_1, 16#08). %  8: BSI + QDS + CP24Time2A                  | Bit string of 32 bit with time tag
-define(M_ME_NA_1, 16#09). %  9: NVA + QDS                               | Measured value, normalized value
-define(M_ME_TA_1, 16#0A). % 10: NVA + QDS + CP24Time2A                  | Measured value, normalized value with time tag
-define(M_ME_NB_1, 16#0B). % 11: SVA + QDS                               | Measured value, scaled value
-define(M_ME_TB_1, 16#0C). % 12: SVA + QDS + CP24Time2A                  | Measured value, scaled value with time tag
-define(M_ME_NC_1, 16#0D). % 13: IEEE STD 754 + QDS                      | Measured value, short floating point
-define(M_ME_TC_1, 16#0E). % 14: IEEE STD 754 + QDS + CP24Time2A         | Measured value, short floating point with time tag
-define(M_IT_NA_1, 16#0F). % 15: BCR                                     | Integrated totals
-define(M_IT_TA_1, 16#10). % 16: BCR + CP24Time2A                        | Integrated totals with time tag
-define(M_EP_TA_1, 16#11). % 17: CP16Time2A + CP24Time2A                 | Protection equipment with time tag
-define(M_EP_TB_1, 16#12). % 18: SEP + QDP + C + CP16Time2A + CP24Time2A | Packed events of protection equipment with time tag
-define(M_EP_TC_1, 16#13). % 19: OCI + QDP + CP16Time2A + CP24Time2A     | Packed output circuit information of protection equipment with time tag
-define(M_PS_NA_1, 16#14). % 20: SCD + QDS                               | Packed single-point information with status change detection
-define(M_ME_ND_1, 16#15). % 21: NVA                                     | Measured value, normalized value without QDS
%% There are no types from 22 to 29
-define(M_SP_TB_1, 16#1E). % 30: SIQ + CP56Time2A                        | Single point information with time tag
-define(M_DP_TB_1, 16#1F). % 31: DIQ + CP56Time2A                        | Double point information with time tag
-define(M_ST_TB_1, 16#20). % 32: VTI + QDS + CP56Time2A                  | Step position information with time tag
-define(M_BO_TB_1, 16#21). % 33: BSI + QDS + CP56Time2A                  | Bit string of 32 bit with time tag
-define(M_ME_TD_1, 16#22). % 34: NVA + QDS + CP56Time2A                  | Measured value, normalized value with time tag
-define(M_ME_TE_1, 16#23). % 35: SVA + QDS + CP56Time2A                  | Measured value, scaled value with time tag
-define(M_ME_TF_1, 16#24). % 36: IEEE STD 754 + QDS + CP56Time2A         | Measured value, short floating point value with time tag
-define(M_IT_TB_1, 16#25). % 37: BCR + CP56Time2A                        | Integrated totals with time tag
-define(M_EP_TD_1, 16#26). % 38: CP16Time2A + CP56Time2A                 | Event of protection equipment with time tag
-define(M_EI_NA_1, 16#46). % 70: Initialization Ending

%% Remote control commands without time tag
-define(C_SC_NA_1, 16#2D). % 45: Single command
-define(C_DC_NA_1, 16#2E). % 46: Double command
-define(C_RC_NA_1, 16#2F). % 47: Regulating step command
-define(C_SE_NA_1, 16#30). % 48: Set point command, normalized value
-define(C_SE_NB_1, 16#31). % 49: Set point command, scaled value
-define(C_SE_NC_1, 16#32). % 50: Set point command, short floating point value
-define(C_BO_NA_1, 16#33). % 51: Bit string 32 bit

%% Remote control commands with time tag
-define(C_SC_TA_1, 16#3A). % 58: Single command (time tag)
-define(C_DC_TA_1, 16#3B). % 59: Double command
-define(C_RC_TA_1, 16#3C). % 60: Regulating step command
-define(C_SE_TA_1, 16#3D). % 61: Set point command, normalized value
-define(C_SE_TB_1, 16#3E). % 62: Set point command, scaled value
-define(C_SE_TC_1, 16#3F). % 63: Set point command, short floating point value
-define(C_BO_TA_1, 16#40). % 64: Bit string 32 bit

%% Remote control commands on system information
-define(C_IC_NA_1, 16#64). % 100: Group Request Command
-define(C_CI_NA_1, 16#65). % 101: Counter Interrogation Command
-define(C_CS_NA_1, 16#67). % 103: Clock Synchronization Command

-endif.