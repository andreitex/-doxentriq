# Owner identity in captured installation code

The captured bootstrap now loads `scripts/identity.py` from the same verified
release as the rest of its operational dependencies. Realm generation no longer
uses an ambient `import identity`. Direct legacy execution loads the explicit
sibling file instead. A substituted module on the Python import path therefore
cannot select the owner recovery policy.

All five operational catalogs include the same 16 modules. The composition
checks retain exact catalog and read-count bounds. Signed helper profile v5
records the corresponding inputs, delivery and composition bytes; profiles
v1–v4 remain historical evidence.

Regression coverage constructs the original captured assembly with a hostile
ambient identity module, checks that the generated owner still requires a
password change, TOTP and recovery-code enrollment, and rejects changed signed
identity bytes before operational execution. Public CI also runs the dependent
source-execution tests so stale fixture pins cannot hide behind narrower
startup checks.

These checks validate code composition and generated policy. They do not prove
a working Keycloak login, live recovery flow, completed installation or reboot
recovery. Those still require the signed deployment and browser acceptance
tests described in [installation readiness](installation-readiness.md).
