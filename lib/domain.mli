(* This Source Code Form is subject to the terms of the Mozilla Public License,
   v. 2.0. If a copy of the MPL was not distributed with this file, You can
   obtain one at https://mozilla.org/MPL/2.0/ *)

module Email : sig
  type t

  val pp :
    Ppx_deriving_runtime.Format.formatter -> t -> Ppx_deriving_runtime.unit

  val show : t -> Ppx_deriving_runtime.string

  val make : string -> (t, string) result

  val to_yojson : t -> Yojson.Safe.t

  val of_yojson : Yojson.Safe.t -> (t, string) result
end

module Hash : sig
  type t

  val make : ?count:int -> ?seed:string -> string -> t

  val verify : string -> t -> (bool, string) result

  val show : t -> string

  val pp : Format.formatter -> t -> unit

  val of_string : string -> t

  val to_yojson : t -> Yojson.Safe.t

  val of_yojson : Yojson.Safe.t -> (t, string) result
end

module Uuid : sig
  type t

  val v4_gen : Random.State.t -> unit -> t

  val show : t -> string

  val pp : Format.formatter -> t -> unit

  val make : string -> (t, string) result

  val to_yojson : t -> Yojson.Safe.t

  val of_yojson : Yojson.Safe.t -> (t, string) result
end

module Member : sig
  type t =
    { id: Uuid.t
    ; username: string option
    ; email: Email.t
    ; hash: Hash.t
    }
  [@@deriving make, show, yojson]

  val id : t -> Uuid.t
end
