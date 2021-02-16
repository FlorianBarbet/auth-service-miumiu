(* This Source Code Form is subject to the terms of the Mozilla Public License,
   v. 2.0. If a copy of the MPL was not distributed with this file, You can
   obtain one at https://mozilla.org/MPL/2.0/ *)
open! Util
module D = Domain
module E = Infra.Environment

module Jwt = struct
  let verify jwt = Jwto.decode_and_verify E.jwt_secret jwt

  let verify_and_get_iss jwt =
    let open Result in
    verify jwt
    >>= fun decoded ->
    let payload = Jwto.get_payload decoded in
    let iss =
      Option.fold ~none:"" ~some:(fun x -> x) @@ Jwto.get_claim "iss" payload
    and exp =
      Option.fold ~none:"" ~some:(fun x -> x) @@ Jwto.get_claim "exp" payload
    and sub =
      Option.fold ~none:"" ~some:(fun x -> x) @@ Jwto.get_claim "sub" payload
    in
    let exp_float =
      Option.fold ~none:0. ~some:(fun x -> x) @@ float_of_string_opt exp
    in
    if iss = E.app_name && exp_float > Unix.time ()
    then Ok sub
    else Error "Invalid token"


  let days_to_timestamp x = x *. 86400.

  let from_member member =
    let payload =
      let iat = Unix.time () in
      [ ("sub", D.Member.id member |> D.Uuid.show)
      ; ("iss", E.app_name)
      ; ("iat", iat |> int_of_float |> string_of_int)
      ; ("exp", iat +. days_to_timestamp 3. |> int_of_float |> string_of_int)
      ]
    in
    Jwto.encode Jwto.HS512 E.jwt_secret payload
end

module Member (MemberRepository : Repository.MEMBER) = struct
  let signup ~email ~password ~username =
    let id = D.Uuid.v4_gen E.random_seed () in
    let hash = D.Hash.make ~seed:E.hash_seed password in
    match D.Email.make email with
    | Error e -> Lwt.return_error e
    | Ok member_email ->
        let open Lwt in
        MemberRepository.create ~id ~hash ~email:member_email ~username
        >>= (function
        | Ok db_result -> Lwt.return_ok ()
        | Error result -> 
          let _ = print_endline (Caqti_error.show result) in Lwt.return_error "Unable to create")


  let signin ~email ~password =
    let hash = D.Hash.make ~seed:E.hash_seed password in
    match D.Email.make email with
    | Error e -> Lwt.return_error e
    | Ok member_email ->
        let open Lwt in
        MemberRepository.get_by_email_hash ~email:member_email ~hash
        >>= (function
        | Ok db_result -> Lwt.return_ok @@ Jwt.from_member db_result
        | Error _ -> Lwt.return_error "Wrong email or password")
  
  let delete ~uuid = 
    let open Lwt in 
    match D.Uuid.make uuid with
    | Error e -> Lwt.return_error e
    | Ok id_member -> 
      MemberRepository.delete ~id:id_member
      >>= (function
      | Ok db_result -> Lwt.return_ok ()
      | Error result -> 
        let _ = print_endline (Caqti_error.show result) in Lwt.return_error "Unable to delete")

  let get_by_id ~uuid =
    let open Lwt in 
    match D.Uuid.make uuid with
    | Error e -> Lwt.return_error e
    | Ok id_member -> 
      MemberRepository.get_by_id ~id:id_member
      >>= (function
      | Ok db_result -> Lwt.return_ok ( D.Member.to_json_string db_result )
      | Error result -> 
        let _ = print_endline (Caqti_error.show result) in Lwt.return_error "An error has occurs")

  let update ~uuid ~email ~password ~username =
    let open Lwt in 
    let getOrDefault opt def converter = match opt with | None -> def | Some str -> (converter str) in  
    match D.Uuid.make uuid with
    | Error e -> Lwt.return_error e
    | Ok id_member -> 
      MemberRepository.get_by_id ~id:id_member
      >>=(function
      | Error result -> 
        let _ = print_endline (Caqti_error.show result) in Lwt.return_error "An error has occurs"
      | Ok db_result -> 
        MemberRepository.update ~id:id_member
         ~email:(getOrDefault email db_result.email (fun e -> match D.Email.make e with | Ok str -> str | Error e -> db_result.email))
         ~hash:(getOrDefault password db_result.hash (fun e -> D.Hash.make ~seed:E.hash_seed e ))
         ~username
         >>=(function
            | Error result -> 
              let _ = print_endline (Caqti_error.show result) in Lwt.return_error "Unable to update"
            | Ok db_result -> Lwt.return_ok ()))


end
