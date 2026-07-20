An unresolved weak reference with a collision-resistant intentionally missing
name is permitted under dynamic lookup and materialized as a weak flat-namespace
GOT bind. Both linkers must leave the slot zero before dyld processing, preserve
weak undefined symbol metadata, and return zero when the provider is absent.
