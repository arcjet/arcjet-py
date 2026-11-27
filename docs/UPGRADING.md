# Upgrading

## Next release

### Unknown sensitive info entity names raise `ValueError`

`detect_sensitive_info` (and `SensitiveInfoDetection`) now raise `ValueError`
when `allow` or `deny` lists a name that is not a built-in
`SensitiveInfoEntityType` and neither a `detect` function nor a `backend` is
configured. Before, such a name was accepted and matched nothing, so the rule
never denied it.

If the name is a misspelled built-in type, correct it, or use the enum:

```python
# Before: "CREDITCARD" matched nothing.
detect_sensitive_info(mode=Mode.LIVE, deny=["CREDITCARD"])

# After:
detect_sensitive_info(
    mode=Mode.LIVE,
    deny=[SensitiveInfoEntityType.CREDIT_CARD_NUMBER],
)
```

If the name is an intentional custom type, pass a `detect` function that returns
it, or a `backend` that detects it:

```python
def detect(tokens: list[str]) -> list[str | None]:
    return ["ACCOUNT_ID" if t.startswith("ACC-") else None for t in tokens]


detect_sensitive_info(mode=Mode.LIVE, deny=["ACCOUNT_ID"], detect=detect)
```

### Names that look like built-in types raise `ValueError`

A name in `allow` or `deny` that looks like a built-in type now raises
`ValueError`, even with a `detect` function or a `backend`. A name looks like a
built-in type when it matches one with case and punctuation ignored, or, at
five or more characters, is a prefix of one or one typo away from it. Use the
built-in type, or give a custom type a name that is not close to a built-in
one.

### Card number detection

Card numbers are detected with the same definition the Arcjet server uses. Some
issuer ranges and lengths are now detected and some are not; see the release
notes for the list.

With `arcjet-sensitive-info-rampart`, card numbers always come from the core
package's card detection. `credit_card_recognizer` is deprecated and no longer
in `default_recognizers`, and card labels from a recognizer or the model are
ignored.
