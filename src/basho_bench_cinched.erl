%% -------------------------------------------------------------------
%%
%% basho_bench: Benchmarking Suite
%%
%% Copyright (c) 2009-2013 Basho Techonologies
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(basho_bench_cinched).

-export([new/1,
         run/4]).

-include("basho_bench.hrl").

-record(url, {abspath, host, port, username, password, path, protocol, host_type}).

-record(state, {
          opt_targets,
          opt_data_key,
          opt_doc,
          opt_encrypted_doc,
          opt_field_query,
          options,
          opt_request_timeout,
          host_index
         }).


%% ====================================================================
%% API
%% ====================================================================

new(_Id) ->
  %% Make sure ibrowse is available
  case code:which(ibrowse) of
    non_existing ->
      ?FAIL_MSG("~s requires ibrowse to be installed.\n", [?MODULE]);
    _ ->
      ok
  end,

  case ssl:start() of
    ok ->
      ok;
    {error, {already_started, ssl}} ->
      ok;
    _ ->
      ?FAIL_MSG("Unable to enable SSL support.\n", [])
  end,

  application:start(ibrowse),
  Ips  = basho_bench_config:get(ips, ["127.0.0.1"]),
  DefaultPort = basho_bench_config:get(port, 55443),
  DataKey = basho_bench_config:get(data_key,"foo"),
  Doc = basho_bench_config:get(doc,"bar"),
  EncryptedDoc = basho_bench_config:get(encrypted_doc,"baz"),
  FieldQuery = basho_bench_config:get(field_query,"buz"),

  Targets = basho_bench_config:normalize_ips(Ips, DefaultPort),
  Urls = [
   [
    {encrypt_blob,#url{host=IP,port=Port,path="/blob/encrypt"}},
    {encrypt_doc,#url{host=IP,port=Port,path="/doc/encrypt?"++FieldQuery}},
    {decrypt_doc,#url{host=IP,port=Port,path="/doc/decrypt?"++FieldQuery}},
    {data_key,#url{host=IP,port=Port,path="/key/data-key"}}
   ] || {IP,Port} <- Targets
  ],

  Options = basho_bench_config:get(options),
  RequestTimeout = basho_bench_config:get(http_raw_request_timeout, 50000),

    {ok, #state {
            opt_targets = Urls,
            opt_data_key = list_to_atom(DataKey),
            opt_doc = Doc,
            opt_encrypted_doc = EncryptedDoc,
            opt_field_query = FieldQuery,
            options = Options,
            opt_request_timeout = RequestTimeout,
            host_index = random:uniform(length(Targets))
           }}.


next_host(State) when State#state.host_index > length(State#state.opt_targets) ->
  next_host(State#state{host_index = 1 });
next_host(State) ->
  { lists:nth(State#state.host_index, State#state.opt_targets),
    State#state{host_index = State#state.host_index + 1 }}.

run(encrypt_blob,_KeyGen,_ValueGen,State0=#state{opt_doc=Doc}) ->
  {Target,State1} = next_host(State0),
  Url = proplists:get_value(encrypt_blob,Target),
  case do_post(
    Url,
    [
     {'Content-Type', 'application/octet-stream'},
     {'Accept', 'application/octet-stream'}
    ],
    Doc,
    State1
   ) of
    ok ->
      {ok, State1};
    {error, Reason} ->
      {error, Reason, State1}
  end;

run(encrypt_doc,_KeyGen,_ValueGen,State0=#state{opt_doc=Doc}) ->
  {Target,State1} = next_host(State0),
  Url = proplists:get_value(encrypt_doc,Target),
  case do_post(
    Url,
    [{'Content-Type', 'application/json'},{'Accept', 'application/json'}],
    Doc,
    State1
   ) of
    ok ->
      {ok, State1};
    {error, Reason} ->
      {error, Reason, State1}
  end;

run(decrypt_doc,_KeyGen,_ValueGen,State0=#state{opt_encrypted_doc=Doc,opt_data_key=DK}) ->
  {Target,State1} = next_host(State0),
  Url = proplists:get_value(decrypt_doc,Target),
  case do_post(
    Url,
    [
     {'Content-Type', 'application/json'},
     {'Accept', 'application/json'},
     {'x-cinched-data-key',DK}
    ],
    Doc,
    State1
   ) of
    ok ->
      {ok, State1};
    {error, Reason} ->
      {error, Reason, State1}
  end;

run(data_key,_KeyGen,_ValueGen,State0) ->
  {Target,State1} = next_host(State0),
  Url = proplists:get_value(data_key,Target),
  case do_post(
    Url,
    [{'Accept', 'application/json'}],
    "",
    State1
   ) of
    ok ->
      {ok, State1};
    {error, Reason} ->
      {error, Reason, State1}
  end.

do_post(Url, Headers, Value, S) ->
    case send_request(Url, Headers,
                      post, Value, [{response_format, binary}], S) of
        {ok, "200", _Header, _Body} ->
            ok;
        {ok, Code, _Header, _Body} ->
            {error, {http_error, Code}};
        {error, Reason} ->
            {error, Reason}
    end.

connect(Url) ->
    case erlang:get({ibrowse_pid, Url#url.host}) of
        undefined ->
            {ok, Pid} = ibrowse_http_client:start({Url#url.host, Url#url.port}),
            erlang:put({ibrowse_pid, Url#url.host}, Pid),
            Pid;
        Pid ->
            case is_process_alive(Pid) of
                true ->
                    Pid;
                false ->
                    erlang:erase({ibrowse_pid, Url#url.host}),
                    connect(Url)
            end
    end.

disconnect(Url) ->
    case erlang:get({ibrowse_pid, Url#url.host}) of
        undefined ->
            ok;
        OldPid ->
            catch(ibrowse_http_client:stop(OldPid))
    end,
    erlang:erase({ibrowse_pid, Url#url.host}),
    ok.

send_request(Url, Headers, Method, Body, Options, S) ->
    send_request(Url, Headers, Method, Body, Options, 3, S).

send_request(_Url, _Headers, _Method, _Body, _Options, 0, _S) ->
    {error, max_retries};
send_request(Url, Headers, Method, Body, Options, Count, S) ->
    Pid = connect(Url),
    case catch(ibrowse_http_client:send_req(Pid, Url, Headers, Method, Body, S#state.options, S#state.opt_request_timeout)) of
        {ok, Status, RespHeaders, RespBody} ->
            {ok, Status, RespHeaders, RespBody};
        Error ->
            lager:debug("Error : ~p",[Error]),
            case should_retry(Error) of
                true ->
                    send_request(Url, Headers, Method, Body, Options, Count-1, S);
                false ->
                    normalize_error(Method, Error)
            end
    end.

should_retry({error, send_failed})       -> true;
should_retry({error, connection_closed}) -> true;
should_retry({'EXIT', {normal, _}})      -> true;
should_retry({'EXIT', {noproc, _}})      -> true;
should_retry(_)                          -> false.

normalize_error(Method, {'EXIT', {timeout, _}})  -> {error, {Method, timeout}};
normalize_error(Method, {'EXIT', Reason})        -> {error, {Method, 'EXIT', Reason}};
normalize_error(Method, {error, Reason})         -> {error, {Method, Reason}}.
