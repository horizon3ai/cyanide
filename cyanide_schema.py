from marshmallow import Schema, fields, post_load, validate
from cyanide_message import CyanideEvent, CyanideEventData, CyanideEventPoisonSource

class CyanideEventPoisonSourceSchema(Schema):
    poisoner = fields.Str(required=True, validate=validate.OneOf(['responder', 'mitm6']))
    target = fields.Str(required=True)
    timestamp = fields.Float(required=True)
    action_state = fields.Str(required=True, validate=validate.OneOf(['NBTNS', 'LLMNR', 'MDNS', 'MITM6']))
    request = fields.Str(required=True)

    @post_load
    def make(self, data, **kwargs):
        return CyanideEventPoisonSource(**data)

class CyanideEventDataSchema(Schema):
    module = fields.Str(required=True)
    source_host = fields.Str(required=False, allow_none=True)
    hash = fields.Str(required=False, allow_none=True)
    type = fields.Str(required=True)
    fullhash = fields.Str(required=False, allow_none=True)
    cleartext = fields.Str(required=False, allow_none=True)
    error_msg = fields.Str(required=False, allow_none=True)
    secretsdump_hashes = fields.Str(required=False, allow_none=True)
    hostname = fields.Str(required=False, allow_none=True)

    @post_load
    def make(self, data, **kwargs):
        return CyanideEventData(**data)

class CyanideEventSchema(Schema):
    poisoner = fields.Str(required=True, validate=validate.OneOf(['responder', 'ntlmrelayx']))
    target = fields.Str(required=True)
    timestamp = fields.Float(required=True)
    action_state = fields.Str(required=True, validate=validate.OneOf(['secretsdump', 'secretsdump_fail', 'captured_hash', 'captured_cleartext']))
    data = fields.Nested(CyanideEventDataSchema, required=True)
    poison_source = fields.Nested(CyanideEventPoisonSourceSchema, required=True)
    user = fields.Str(required=True)

    @post_load
    def make(self, data, **kwargs):
        return CyanideEvent(**data)