(* This Source Code Form is subject to the terms of the Mozilla Public License,
   v. 2.0. If a copy of the MPL was not distributed with this file, You can
   obtain one at https://mozilla.org/MPL/2.0/ *)

open Opium

(** Bind dependencies *)

module Connection = (val Infra.Database.connect ())

module PostgresRepository = Repository.Member (Connection)
module MemberServive = Service.Member (PostgresRepository)

let set_logger () =
  Logs.set_reporter (Logs_fmt.reporter ()) ;
  Logs.set_level Infra.Environment.log_level


(** Heartbeat route *)
let root req =
  Printf.sprintf "Welcome to auth server"
  |> Response.of_plain_text
  |> Lwt.return


(** Testing purpose route *)
let echo req =
  let open Lwt in
  req
  |> Request.to_json
  >>= fun json ->
  let body = Option.get json |> Yojson.Safe.to_string |> Body.of_string in
  Response.make ~body () |> Lwt.return


(** Singnup route *)
let signup req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> Response.make ~status:`Bad_request () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let email = json |> member "email" |> to_string
      and password = json |> member "password" |> to_string in
      MemberServive.signup ~email ~password
      >>= (function
      | Error e ->
          Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
          |> Lwt.return
      | Ok _ -> Response.make ~status:`Created () |> Lwt.return)


(** Singnin route *)
let signin req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> Response.make ~status:`Bad_request () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let email = json |> member "email" |> to_string
      and password = json |> member "password" |> to_string in
      MemberServive.signin ~email ~password
      >>= (function
      | Error e ->
          Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
          |> Lwt.return
      | Ok jwt ->
          ( match jwt with
          | Error e ->
              Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
              |> Lwt.return
          | Ok jwt_string ->
              Response.make ~status:`OK ~body:(Body.of_string jwt_string) ()
              |> Lwt.return ))


(** Jwt verification route *)

let verify req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> Response.make ~status:`Bad_request () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let jwt = json |> member "jwt" |> to_string in
      ( match Service.Jwt.verify_and_get_iss jwt with
      | Error e ->
          Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
          |> Lwt.return
      | Ok iss ->
          Response.make ~status:`OK ~body:(Body.of_string iss) () |> Lwt.return
      )


let routes =
  [ App.get "/" root
  ; App.post "/echo" echo
  ; App.post "/signup" signup
  ; App.post "/signin" signin
  ; App.post "/verify" verify
  ]


let add_routes app = List.fold_left (fun app route -> route app) app routes
