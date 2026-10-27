# Releasing

How a release is made. This is for the maintainer; nothing here is needed to use or build Zarp.

Releases are built **locally** by `scripts/package.sh` and uploaded by hand. They cannot be built on a hosted
runner because the app and its embedded daemon are signed with the maintainer's Apple Development
certificate, which stays on the maintainer's Mac.

- [Decisions that shape a release](#decisions-that-shape-a-release)
- [Checklist](#checklist)
- [Release notes template](#release-notes-template)
- [After the release](#after-the-release)

## Decisions that shape a release

- **Unnotarized.** There is no paid Apple Developer Program membership behind the project, so the disk image
  is signed with a free *Apple Development* certificate and is not notarized. Users get Gatekeeper's "was
  blocked" prompt on first launch; the steps are in the README, in
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and, in short, on the window of the disk image itself
  (`scripts/dmg/`). This is a deliberate trade-off, not an oversight.
- **A free certificate lasts one year.** An app signed with an expired certificate keeps running, but a new
  build needs a fresh one (Xcode creates it).
- **The signature carries a name.** A development certificate's subject is `Apple Development: <the Apple ID's
  name or email> (<id>)`, and anyone can read it from the finished app with `codesign -dvv Zarp.app`. If that
  is not something you want public, sign with an Apple ID set up for the project.
- **Apple Silicon only, macOS 14+**, matching the daemon's arm64-only build.

## Checklist

1. **Decide the version** using semantic versioning. Set `MARKETING_VERSION` in
   [`project.yml`](../project.yml) (and bump `CURRENT_PROJECT_VERSION` by one). The daemon is stamped with the
   same version, and the app uses it to notice a stale daemon after an update.
2. **Write the changelog.** Move the *Unreleased* entries in [`CHANGELOG.md`](../CHANGELOG.md) under the new
   version and date, and fix the compare links at the bottom.
3. **Run the checks.**

   ```sh
   make test                    # Go, Swift, documentation links
   scripts/gen-notices.sh --check
   ```

   System testing is performed by the maintainer after choosing when to stop
   other VPNs. Record its actual result separately from loopback/build checks.
   A build must not describe an unperformed system test as passed. Current
   evidence and remaining limits are in [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).
4. **Build the image.**

   ```sh
   make dmg                     # scripts/package.sh: tests, clean Release build, checks, DMG
   ```

   `package.sh` refuses to continue unless the tests pass, the notices are current, the bundle has the
   daemon, the icon, the languages, the blobs and the licences, both binaries are arm64-only, the app and the
   daemon share a Team ID, and the daemon reports the app's version. It then verifies the image and that the
   signature survives inside it, and writes `build/Zarp-<version>-arm64.dmg` and its `.sha256`.

   The image opens as a drag-to-Applications window (background, icon positions, volume icon). That layout
   is written by [dmgbuild](https://github.com/dmgbuild/dmgbuild), which `package.sh` installs into
   `build/.dmgbuild-venv` the first time (it needs `python3` and a network once; `pip3 install dmgbuild`
   works too). The artwork is `scripts/dmg/background*.png`, redrawn with `make dmg-art`; the icon positions
   are in `scripts/dmg/settings.py` and must agree with it.
5. **Smoke-test the artifact** as a user would: open the image (it should show the install window: Zarp, an
   arrow and Applications), drag the app to `/Applications` (replacing a development copy), pass Gatekeeper, approve automatic service preparation when macOS requests it, connect, browse, disconnect, and
   check that the network is back to normal. This is the step that catches packaging problems the script
   cannot.
6. **Commit and tag.**

   ```sh
   VERSION=1.0.0                      # the version you are releasing
   git remote set-url origin https://github.com/ZarpVPN/Zarp-MacOS.git
   git add -A
   git diff --cached --check
   git commit -m "Release $VERSION"
   git fetch origin
   git rebase origin/main
   git tag -a "v$VERSION" -m "Zarp for macOS $VERSION"
   git push --atomic origin main "v$VERSION"
   ```

   The current checkout has eleven patch-equivalent local commits and four
   additional upstream README commits. The prepared README preserves both sets
   of changes. Rebase skips the duplicate patches and places the release on
   the updated `origin/main`. Complete any reported conflict before tagging or
   pushing. Publish only the intended release tag.

7. **Publish the release** on GitHub with the image and its checksum attached. Publish a normal release, not
   a pre-release: the README's download button points to `releases/latest`, and GitHub resolves that to the
   newest release that is *not* marked as a pre-release.

   ```sh
   gh release create "v$VERSION" "build/Zarp-$VERSION-arm64.dmg" "build/Zarp-$VERSION-arm64.dmg.sha256" \
     --repo ZarpVPN/Zarp-MacOS --verify-tag --latest \
     --title "Zarp for macOS $VERSION" --notes-file "docs/releases/$VERSION.md"
   ```

   `gh` is not installed by default: `brew install gh`, then `gh auth login` once. Without it, use the
   *Draft a new release* page instead (`https://github.com/ZarpVPN/Zarp-MacOS/releases/new?tag=v1.0.0`, which
   also accepts `title` and `body` query parameters), choose the existing tag, paste the notes and drag the
   two files in.

   The exact 1.0.0 notes are in [releases/1.0.0.md](releases/1.0.0.md).
   Compare the image checksum with the local release-verification report before
   uploading. The build and checksum stay under ignored `build/`; attach them
   as release assets rather than committing the binaries.

## Release notes template

```markdown
## Zarp for macOS <version>

<two or three lines: what is new, why you might care>

### Changes
- ...

### Install
Download `Zarp-<version>-arm64.dmg`, drag Zarp to Applications and follow the first-launch steps in the README.
The release is **not notarized**: macOS will block the first launch, and the README explains how to open it.
Requires an Apple Silicon Mac and macOS 14 or later (developed and tested on macOS 15).

### Verify
SHA-256 of `Zarp-<version>-arm64.dmg`:

    <paste the contents of the .sha256 file>

Full list of changes: [CHANGELOG.md](CHANGELOG.md#<anchor>).
```

## After the release

- Check that the README's download link and the badges resolve to the new release.
- Add an empty *Unreleased* section back to the changelog if the release commit removed it.
- Keep the built `.dmg` and its checksum: they are the exact bytes users verify against.
