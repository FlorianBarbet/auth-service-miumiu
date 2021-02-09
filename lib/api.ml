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
      and password = json |> member "password" |> to_string
      and username = json |> member "username" |> to_string_option in
      MemberServive.signup ~email ~password ~username
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

 (*factorisation*)
 let check_auth action req=     
  let open Lwt in
  let uuid = Router.param req "id" in
  req
  |> Request.to_json
  >>= function
  | None -> Response.make ~status:`Bad_request () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let jwt = match Request.header "Authorization" req with | Some str -> str | None -> ""  in
      ( match Service.Jwt.verify_and_get_iss jwt with
      | Error e ->
          Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
          |> Lwt.return
      | Ok _ -> action ~uuid ~req
      )
(* as member I want be able to delete my account *)
let delete_member ~uuid ~req = 
  let open Lwt in
  MemberServive.delete ~uuid
  >>= (function
  | Error e ->
      Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
      |> Lwt.return
  | Ok _ -> Response.make ~status:`OK () |> Lwt.return) 

(* as member I want be able to get my account informations *)
let get_member ~uuid ~req= 
  let open Lwt in
  let open Yojson.Safe.Util in
  MemberServive.get_by_id ~uuid
  >>= (function
  | Error e ->
      Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
      |> Lwt.return
  | Ok res -> Response.of_json res|> Lwt.return) 
(* as member I want be able to update my account informations *)
let update ~uuid ~req=
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> Response.make ~status:`Bad_request () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let email = json |> member "email" |> to_string_option
      and password = json |> member "password" |> to_string_option
      and username = json |> member "username" |> to_string_option in
  MemberServive.update ~uuid ~email ~password ~username
  >>= (function
  | Error e ->
      Response.make ~status:`Forbidden ~body:(Body.of_string e) ()
      |> Lwt.return
  | Ok _ -> Response.make ~status:`OK () |> Lwt.return) 

let routes =
  [ App.get "/" root
  ; App.post "/echo" echo
  ; App.post "/signup" signup
  ; App.post "/signin" signin
  ; App.post "/verify" verify
  ; App.delete "/member/:id" (check_auth delete_member)
  ; App.get "/member/:id" (check_auth get_member)
  ; App.put "/member/:id" (check_auth update)
  ]


let add_routes app = List.fold_left (fun app route -> route app) app routes
