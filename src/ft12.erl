%%% +----------------------------------------------------------------+
%%% | Copyright (c) 2024. Tokenov Alikhan, alikhantokenov@gmail.com  |
%%% | All rights reserved.                                           |
%%% | License can be found in the LICENSE file.                      |
%%% +----------------------------------------------------------------+

-module(ft12).
-include("ft12_sniffer.hrl").

%%% +--------------------------------------------------------------+
%%% |                           API                                |
%%% +--------------------------------------------------------------+

-export([
  check_settings/1,
  start_link/1,
  send/2,
  stop/1
]).

%%% +--------------------------------------------------------------+
%%% |                           Macros                             |
%%% +--------------------------------------------------------------+

-record(state, {
  name,
  owner,
  connection,
  type,
  buffer,
  address_size
}).

-define(DEFAULT_PORT_OPTIONS, #{
  name => undefined,
  mode => active,
  baudrate => 9600,
  parity => 0,
  stopbits => 1,
  bytesize => 8
}).

-define(DEFAULT_OPTIONS, #{
  transport => ?DEFAULT_PORT_OPTIONS,
  address_size => 1
}).

-define(CONNECT_TIMEOUT, 5000).
-define(START_DATA_CHAR, 16#68).
-define(START_CMD_CHAR, 16#10).
-define(END_CHAR, 16#16).

%%% +--------------------------------------------------------------+
%%% |                      API Implementation                      |
%%% +--------------------------------------------------------------+

start_link(InOptions) ->
  Options = maps:merge(?DEFAULT_OPTIONS, InOptions),
  check_settings(Options),
  Self = self(),
  PID = spawn_link(fun() -> init(Self, Options) end),
  receive
    {ready, PID} ->
      PID;
    {'EXIT', PID, Reason} ->
      ?LOGERROR("FT12 failed to start w/ reason: ~p", [Reason]),
      throw({error, Reason})
  end.

send(Port, Frame) ->
  case is_process_alive(Port) of
    true ->
      Port ! {send, self(), Frame},
      ok;
    _ ->
      ?LOGWARNING("FT12. send error: port is closed"),
      throw(port_is_closed)
  end.

stop(PortFT12) ->
  catch exit(PortFT12, shutdown).

%%% +--------------------------------------------------------------+
%%% |                      Internal functions                      |
%%% +--------------------------------------------------------------+

init(Owner, #{
  transport := #{
    type := Type,
    name := String
  },
  address_size := AddressSize
} = ConnectionSettings) ->
  case start_connection(ConnectionSettings) of
    {ok, Connection} ->
      Owner ! {ready, self()},
      loop(#state{
        name = String,
        owner = Owner,
        type = Type,
        connection = Connection,
        address_size = AddressSize * 8,
        buffer = <<>>
      });
    {error, ConnectionError} ->
      exit(ConnectionError)
  end.

start_connection(#{
  transport := #{
    type := tcp,
    name := String
  }
}) ->
  {ok, {Host, Port}} = parse_tcp_setting(String),
  ?LOGDEBUG("FT12 ~p: trying to connect...", [String]),
  case gen_tcp:connect(Host, Port, [binary, {active, true}, {packet, raw}], ?CONNECT_TIMEOUT) of
    {ok, Socket} ->
      ?LOGDEBUG("FT12 ~p: socket ~p is opened!", [String, Socket]),
      {ok, Socket};
    {error, Error} ->
      ?LOGERROR("FT12 ~p: failed to connect to socket, error: ~p", [String, Error]),
      {error, Error}
  end;

start_connection(#{
  transport := #{
    type := serial,
    name := Name
  } = PortOptions
}) ->
  ?LOGDEBUG("FT12 ~p: trying to open eserial...", [Name]),
  case eserial:open(Name, maps:without([type, name], PortOptions)) of
    {ok, SerialPort} ->
      ?LOGDEBUG("FT12 ~p: eserial is opened!", [Name]),
      {ok, SerialPort};
    {error, Error} ->
      ?LOGERROR("FT12 ~p: failed to start eserial, error: ~p", [Name, Error]),
      {error, Error}
  end.

loop(#state{
  name = Name,
  connection = Connection,
  type = Type,
  owner = Owner,
  buffer = Buffer,
  address_size = AddressSize
} = State) ->
  receive
    {tcp, Connection, Data} ->
      TailBuffer = parse(Owner, Name, <<Buffer/binary, Data/binary>>, AddressSize),
      ?LOGDEBUG("FT12 ~p: tail buffer: ~p", [Name, TailBuffer]),
      loop(State#state{buffer = TailBuffer});

    {Connection, data, Data} ->
      TailBuffer = parse(Owner, Name, <<Buffer/binary, Data/binary>>, AddressSize),
      ?LOGDEBUG("FT12 ~p: tail buffer: ~p", [Name, TailBuffer]),
      loop(State#state{buffer = TailBuffer});

    {send, Owner, Frame} ->
      OutState =
        case Frame#frame.control_field of
          % If the request is reset remote link then we delete all the data from the buffer
          #control_field_request{function_code = _ResetLink = 0} ->
            % TODO: ClearWindow should be calculated from the baudrate
            timer:sleep(_ClearWindow = 100),
            drop_data(Connection),
            State#state{buffer = <<>>};
          _ ->
            State
        end,
      Packet = build_frame(Frame, AddressSize),
      ?LOGDEBUG("FT12 ~p: sending frame: ~p, packet ~p", [Name, Frame, Packet]),
      send(Type, Connection, Packet),
      loop(OutState);

    {tcp_closed, Connection} ->
      ?LOGERROR("FT12 ~p: tcp closed", [Name]),
      exit(closed);
    {tcp_error, Connection, Reason} ->
      ?LOGERROR("FT12 ~p: tcp error: ~p", [Name, Reason]),
      exit(Reason);
    {tcp_passive, Connection} ->
      ?LOGERROR("FT12 ~p: tcp passive", [Name]),
      exit(tcp_passive);

    Unexpected ->
      ?LOGWARNING("FT12 ~p: unexpected message received ~p", [Name, Unexpected]),
      loop(State)
  end.

close_connection(tcp, Socket) ->
  gen_tcp:close(Socket);
close_connection(serial, SerialPort) ->
  eserial:close(SerialPort).

send(tcp, Socket, Data) ->
  case gen_tcp:send(Socket, Data) of
    ok ->
      ok;
    {error, Error} ->
      close_connection(tcp, Socket),
      exit(Error)
  end;
send(serial, SerialPort, Data) ->
  eserial:send(SerialPort, Data).

parse(Owner, Name, BinaryData, AddressSize) ->
  case parse_frame(BinaryData, AddressSize) of
    {#frame{} = Frame, Tail} ->
      ?LOGDEBUG("FT12 ~p: received frame: ~p, data ~p", [Name, Frame, build_frame( Frame, AddressSize )]),
      Owner ! {data, self(), Frame},
      Tail;
    {_NoFrame, Tail} ->
      Tail
  end.

parse_frame(Buffer, AddressSize) ->
  parse_frame(Buffer, AddressSize, none).

parse_frame(<<
  ?START_CMD_CHAR,
  _/binary
>> = Buffer, AddressSize, LastFrame) ->
  case Buffer of
    <<?START_CMD_CHAR, ControlField, Address:AddressSize/little-integer, Checksum, ?END_CHAR, Tail/binary>> ->
      case control_sum(<<ControlField, Address:AddressSize/little-integer>>) of
        Checksum ->
          case parse_control_field(<<ControlField>>) of
            error ->
              ?LOGERROR("invalid control field: ~p", [ControlField]),
              parse_frame(Tail, AddressSize, LastFrame);
            CFRec ->
              parse_frame(Tail, AddressSize, #frame{
                address = Address,
                control_field = CFRec,
                data = undefined
              })
          end;
        Sum ->
          ?LOGERROR("invalid control sum: ~p", [Sum]),
          parse_frame(Tail, AddressSize, LastFrame)
      end;
    _ ->
      if
      % Frame length
        size(Buffer) < (4 + AddressSize) ->
          {LastFrame, Buffer};
        true ->
          <<_, TailBuffer/binary>> = Buffer,
          parse_frame(TailBuffer, AddressSize, LastFrame)
      end
  end;
parse_frame(<<
  ?START_DATA_CHAR,
  LengthL:8,
  LengthL:8,
  ?START_DATA_CHAR,
  Body/binary
>> = Buffer, AddressSize, LastFrame) ->
  case Body of
    <<FrameData:LengthL/binary, Checksum, ?END_CHAR, Tail/binary>> ->
      case control_sum(FrameData) of
        Checksum ->
          <<ControlField, Address:AddressSize/little-integer, Data/binary>> = FrameData,
          case parse_control_field(<<ControlField>>) of
            error ->
              ?LOGERROR("invalid control field ~p", [ControlField]),
              parse_frame(Tail, AddressSize, LastFrame);
            CF ->
              parse_frame(Tail, AddressSize, #frame{
                address = Address,
                control_field = CF,
                data = Data
              })
          end;
        _ ->
          ?LOGERROR("invalid control sum"),
          parse_frame(Tail, AddressSize, LastFrame)
      end;
    _ ->
      if
      % Frame length
        size(Body) < (2 + LengthL) ->
          {LastFrame, Buffer};
        true ->
          <<_, TailBuffer/binary>> = Buffer,
          parse_frame(TailBuffer, AddressSize, LastFrame)
      end
  end;
parse_frame(<<?START_DATA_CHAR, _/binary>> = Buffer, _AddressSize, LastFrame) when size(Buffer) < 4 ->
  {LastFrame, Buffer};
parse_frame(<<_, Tail/binary>>, AddressSize, LastFrame) ->
  parse_frame(Tail, AddressSize, LastFrame);
parse_frame(<<>>, _AddressSize, LastFrame) ->
  {LastFrame, <<>>}.

parse_control_field(<<DIR:1, 1:1, FCB:1, FCV:1, FunctionCode:4>>) ->
  #control_field_request{
    direction = DIR,
    fcb = FCB,
    fcv = FCV,
    function_code = FunctionCode
  };

parse_control_field(<<DIR:1, 0:1, ACD:1, DFC:1, FunctionCode:4>>) ->
  #control_field_response{
    direction = DIR,
    acd = ACD,
    dfc = DFC,
    function_code = FunctionCode
  };

parse_control_field(_Invalid) ->
  error.

build_frame(#frame{address = Address, control_field = CFRec, data = Data}, AddressSize) when is_binary(Data) ->
  Body = <<
    (build_control_field(CFRec))/binary,
    Address:AddressSize/little-integer,
    Data/binary
  >>,
  Length = size(Body),
  Checksum = control_sum(Body),
  <<?START_DATA_CHAR, Length, Length, ?START_DATA_CHAR, Body/binary, Checksum, ?END_CHAR>>;

build_frame(#frame{address = Address, control_field = CFRec}, AddressSize) ->
  Body = <<
    (build_control_field(CFRec))/binary,
    Address:AddressSize/little-integer
  >>,
  Checksum = control_sum(Body),
  <<?START_CMD_CHAR, Body/binary, Checksum, ?END_CHAR>>.

build_control_field(#control_field_request{
  direction = DIR,
  fcb = FCB,
  fcv = FCV,
  function_code = FunctionCode
}) ->
  <<DIR:1, 1:1, FCB:1, FCV:1, FunctionCode:4>>;

build_control_field(#control_field_response{
  direction = DIR,
  acd = ACD,
  dfc = DFC,
  function_code = FunctionCode
}) ->
  <<DIR:1, 0:1, ACD:1, DFC:1, FunctionCode:4>>.

%% Calculating control sum of the received packet to verify it
control_sum(Data) ->
  control_sum(Data, 0).

control_sum(<<Head, Rest/binary>>, Sum) ->
  control_sum(Rest, Sum + Head);
control_sum(<<>>, Sum) ->
  Sum rem 256.

%% Clear the process mailbox of these messages
drop_data(Connection) ->
  receive
    {tcp, Connection, _Data} -> drop_data(Connection);
    {Connection, data, _Data} -> drop_data(Connection)
  after
    0 -> ok
  end.

check_settings(#{transport := TransportSettings}) ->
  case TransportSettings of
    #{type := Type} when (Type =:= tcp) orelse (Type =:= serial) ->
      [check_setting(Type, Setting) || Setting <- maps:to_list(maps:without([type], TransportSettings))];
    Other ->
      throw({invalid_transport_type, Other})
  end,
  ok.

check_setting(tcp, {name, String})
  when is_list(String) -> ok;

check_setting(serial, {name, Name})
  when is_list(Name) -> ok;

check_setting(serial, {baudrate, Baudrate})
  when is_integer(Baudrate) -> ok;

check_setting(serial, {parity, Parity})
  when is_integer(Parity) -> ok;

check_setting(serial, {bytesize, Bytesize})
  when is_integer(Bytesize) -> ok;

check_setting(serial, {stopbits, Stopbits})
  when is_integer(Stopbits) -> ok;

check_setting(Type, Option) ->
  throw({invalid_setting, Type, Option}).

parse_tcp_setting(String) ->
  [Host, Port] = string:split(String, ":"),
  {ok, Address} = inet:parse_address(Host),
  {ok, {Address, list_to_integer(Port)}}.