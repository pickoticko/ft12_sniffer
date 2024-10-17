%%% +----------------------------------------------------------------+
%%% | Copyright (c) 2024. Tokenov Alikhan, alikhantokenov@gmail.com  |
%%% | All rights reserved.                                           |
%%% | License can be found in the LICENSE file.                      |
%%% +----------------------------------------------------------------+

-module(ft12_parser).
-include("ft12_sniffer.hrl").

%%% +--------------------------------------------------------------+
%%% |                            API                               |
%%% +--------------------------------------------------------------+

-export([
  get_settings/1,
  parse/2
]).

%%% +--------------------------------------------------------------+
%%% |                           Macros                             |
%%%Ғ +--------------------------------------------------------------+

%% SQ (Structure Qualifier) bit specifies how information are addressed
-define(SQ_DISCONTINUOUS, 0).
-define(SQ_CONTINUOUS, 1).

%% Packet capacity
-define(MAX_PACKET_BYTE_SIZE, 255).

%% Constant sizes of header content
-define(TRANSPORT_CONSTANT_COST, 4).
-define(ASDU_CONSTANT_COST, 3).

%%% +--------------------------------------------------------------+
%%% |                         Implementation                       |
%%% +--------------------------------------------------------------+

parse(ASDU, #{
  information_object_address_size := IOABitSize,
  originator_address_size := ORGBitSize,
  common_address_size := COABitSize
}) ->
  {DUI, ObjectsBinary} = parse_dui(COABitSize, ORGBitSize, ASDU),
  Objects = construct_sequence(DUI, IOABitSize, ObjectsBinary),
  #{
    type := Type,
    t    := T,
    pn   := PN,
    cot  := COT,
    org  := ORG,
    coa  := COA
  } = DUI,
  ParsedObjects =
    [begin
       {Address, ft12_type:parse_information_element(Type, Object)}
     end || {Address, Object} <- Objects]
  #asdu{
    type = Type,
    pn = PN,
    t = T,
    cot = COT,
    org = ORG,
    coa = COA,
    objects = ParsedObjects
  }.

%% Bytes conversion to bits
get_settings(#{
  coa_size := COASize,
  org_size := ORGSize,
  ioa_size := IOASize
} = Settings) ->
  Settings#{
    coa_size => bytes_to_bits(COASize),
    org_size => bytes_to_bits(ORGSize),
    ioa_size => bytes_to_bits(IOASize)
  }.

%% +--------------------------------------------------------------+
%% |                 Internal helper functions                    |
%% +--------------------------------------------------------------+

construct_sequence(#{sq := ?SQ_CONTINUOUS, no := NumberOfObjects}, IOASize, ObjectsBinary) ->
  <<Start:IOASize/little-integer, Sequence/binary>> = ObjectsBinary,
  ObjectSize = round(bytes_to_bits(size(Sequence) / NumberOfObjects)),
  ObjectsList = [<<Object:ObjectSize>> || <<Object:ObjectSize>> <= Sequence],
  lists:zip(lists:seq(Start, Start + NumberOfObjects - 1), ObjectsList);

construct_sequence(#{sq := ?SQ_DISCONTINUOUS, no := NumberOfObjects}, IOASize, ObjectsBinary) ->
  ObjectSize = round((bytes_to_bits(size(ObjectsBinary)) - IOASize * NumberOfObjects) / NumberOfObjects),
  [{Address, <<Object:ObjectSize>>} || <<Address:IOASize/little-integer, Object:ObjectSize>> <= ObjectsBinary].

%% +--------------[ DUI Structure ]--------------+
%% | Type Identification (TypeID) - 1 byte       |
%% | Structure Qualifier (SQ)     - 1 bit        |
%% | Number of Objects   (NO)     - 7 bits       |
%% | Test                         - 1 bit        |
%% | Positive / Negative (P/N)    - 1 bit        |
%% | Cause of Transmission (COT)  - 6 bits       |
%% | Originator Address (ORG)     - 0 or 1 byte  |
%% | Common Address (COA)         - 1 or 2 bytes |
%% | ...Information objects...                   |
%% +---------------------------------------------+

%% Data Unit Identifier (DUI) parser
parse_dui(COASize, ORGSize,
  <<Type:8,
    SQ:1, NumberOfObjects:7,
    T:1, PN:1, COT:6,
    Rest/binary>>
) ->
  <<ORG:ORGSize,
    COA:COASize/little-integer,
    Body/binary>> = Rest,
  DUI = #{
    type => Type,
    sq   => SQ,
    no   => NumberOfObjects,
    t    => T,
    pn   => PN,
    cot  => COT,
    org  => ORG,
    coa  => COA
  },
  {DUI, Body};

parse_dui(_COASize, _ORGSize, InvalidASDU) ->
  throw({invalid_asdu_format, InvalidASDU}).

bytes_to_bits(Bytes) -> Bytes * 8.
