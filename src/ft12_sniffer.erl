%%% +----------------------------------------------------------------+
%%% | Copyright (c) 2024. Tokenov Alikhan, alikhantokenov@gmail.com  |
%%% | All rights reserved.                                           |
%%% | License that can be found in the LICENSE file.                 |
%%% +----------------------------------------------------------------+

-module(ft12_sniffer).
-include("ft12_sniffer.hrl").

-export([
  start_link/1
]).

-record(state, {
  master,
  slave,
  parser_settings
}).

start_link(Configuration) ->
  {ok, spawn_link(fun() -> init_sniffer(Configuration) end)}.

init_sniffer(#{
  master := MasterConfig,
  slave := SecondConfig,
  parser_settings := ParserSettings
}) ->
  ?LOGINFO("Initializing sniffer..."),
  Master = ft12:start_link(MasterConfig),
  ?LOGINFO("Started master FT12, pid: ~p", [Master]),
  Slave = ft12:start_link(SecondConfig),
  ?LOGINFO("Started slave FT12, pid: ~p", [Slave]),
  sniffer_loop(#state{
    master = Master,
    slave = Slave,
    parser_settings = ParserSettings
  }).

sniffer_loop(#state{
  master = Master,
  slave = Slave
} = State) ->
  receive
    {data, From, Frame} ->
      SendTo =
        case From of
          Master -> Slave;
          Slave -> Master
        end,
      try log_frame(From, Frame, State) catch
        _Exception:Error -> ?LOGINFO("failed to log frame: ~p, error: ~p", [Frame, Error])
      end,
      ft12:send(SendTo, Frame);
    Unexpected ->
      ?LOGWARNING("received unexpected message: ~p", [Unexpected])
  end,
  sniffer_loop(State).

log_frame(From, #frame{
  address = Address,
  control_field = ControlField,
  data = Data
}, #state{
  master = Master,
  slave = Slave,
  parser_settings = ParserSettings
}) when is_binary(Data) ->
  #asdu{
    type = Type,
    pn = PN,
    t = T,
    cot = COT,
    org = ORG,
    coa = COA,
    objects = ParsedObjects
  } = ft12_sniffer_parser:parse(Data, ParserSettings),
  Name =
    case From of
      Master -> "MASTER";
      Slave -> "SLAVE"
    end,
  LogFormat = Name ++ " address: ~p, cf: ~p, ASDU[type: ~p, pn: ~p, t: ~p, cot: ~p, org: ~p, coa: ~p, objects: ~p]",
  ?LOGINFO(LogFormat, [
    Address,
    ControlField,
    Type,
    PN,
    T,
    COT,
    ORG,
    COA,
    ParsedObjects
  ]);

log_frame(From, #frame{
  address = Address,
  control_field = ControlField,
  data = Data
}, #state{
  master = Master,
  slave = Slave
}) when is_binary(Data) ->
  Name =
    case From of
      Master -> "MASTER";
      Slave -> "SLAVE"
    end,
  LogFormat = Name ++ " address: ~p, cf: ~p",
  ?LOGINFO(LogFormat, [Address, ControlField]).