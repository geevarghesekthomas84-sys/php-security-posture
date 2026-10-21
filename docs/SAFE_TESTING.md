# Safe testing

This repository validates exposure through configuration, benign health checks,
and synthetic telemetry. It intentionally does not include exploit payloads.

## Test layers

1. **Configuration checks** inspect PHP versions and effective settings.
2. **GET-only checks** read an approved health endpoint and never send POST or
   multipart data.
3. **Synthetic logs** exercise the investigation rules without touching a
   production log.
4. **Misconfigured lab profile** demonstrates what a failing posture report
   looks like in a disposable container.

Run the fixture tests with:

```bash
make fixtures
```

The insecure PHP profile is for local regression testing only. It is not an
exploit target and must never be deployed.
