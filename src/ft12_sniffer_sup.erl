%%% +----------------------------------------------------------------+
%%% | Copyright (c) 2024. Tokenov Alikhan, alikhantokenov@gmail.com  |
%%% | All rights reserved.                                           |
%%% | License that can be found in the LICENSE file.                 |
%%% +----------------------------------------------------------------+

-module(ft12_sniffer_sup).
-include("ft12_sniffer.hrl").

-export([
  start_link/0,
  init/1
]).

-define(DEFAULT_MAX_RESTARTS, 10).
-define(DEFAULT_MAX_PERIOD, 1000).
-define(DEFAULT_STOP_TIMEOUT, 600000).

-define(SNIFFER_FT12_WORKER(Config), #{
  id => sniffer,
  start => {ft12_sniffer, start_link, [Config]},
  restart => permanent,
  shutdown => ?DEFAULT_STOP_TIMEOUT,
  type => worker,
  modules => [ft12_sniffer]
}).

-define(SNIFFER_SUPERVISOR, #{
  strategy => one_for_all,
  intensity => ?DEFAULT_MAX_RESTARTS,
  period => ?DEFAULT_MAX_PERIOD
}).

start_link() ->
  ?LOGINFO("Starting sniffer..."),
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  Configuration = ?ENV(sniffer, #{}),
  {ok, {?SNIFFER_SUPERVISOR, [?SNIFFER_FT12_WORKER(Configuration)]}}.