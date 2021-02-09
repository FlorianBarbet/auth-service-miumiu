(* This Source Code Form is subject to the terms of the Mozilla Public License,
   v. 2.0. If a copy of the MPL was not distributed with this file, You can
   obtain one at https://mozilla.org/MPL/2.0/ *)

module Email = struct
  type t = Emile.address [@@deriving show]

  let make email =
    let maked_email = Emile.address_of_string email in
    match maked_email with
    | Ok address -> Ok address
    | Error _ -> Error "Invalid_Email"


  let to_yojson email = Yojson.Safe.from_string @@ show email

  let of_yojson json = make @@ Yojson.Safe.to_string json
end

module Hash = struct
  type t = Bcrypt.hash

  let make = Bcrypt.hash

  let verify password hash =
    if Bcrypt.verify password hash then Ok true else Error "Invalid_Password"


  let show = Bcrypt.string_of_hash

  let pp ppf hash = Format.pp_print_string ppf (show hash)

  let of_string = Bcrypt.hash_of_string

  let to_yojson hash = Yojson.Safe.from_string @@ show hash

  let of_yojson json = Ok (make @@ Yojson.Safe.show json)
end

module Uuid = struct
  include Uuidm

  let make uuid_string =
    Uuidm.of_string uuid_string |> Option.to_result ~none:"Invalid_Uuid"


  let show u = to_string u

  let to_yojson uuid = Yojson.Safe.from_string @@ show uuid

  let of_yojson json = make @@ Yojson.Safe.to_string json
end

module Member = struct
  type t =
    { id: Uuid.t
    ; username: string option
    ; email: Email.t
    ; hash: Hash.t
    }
  [@@deriving make, show, yojson]

  let id member = member.id
end
