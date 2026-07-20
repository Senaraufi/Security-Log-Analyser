# Homebrew formula for logr.
#
# This is a TEMPLATE. To publish a Homebrew tap:
#   1. Create a public repo named `homebrew-tap` under your account
#      (e.g. github.com/senaraufi/homebrew-tap).
#   2. Copy this file to `Formula/logr.rb` in that repo.
#   3. After each release, update `version`, the `url`s, and the `sha256`
#      values below using the `*.sha256` files attached to the GitHub Release.
#
# Users then install with:
#   brew install senaraufi/tap/logr
#
# The sha256 placeholders MUST be replaced with the real checksums from the
# release assets (see the `<asset>.tar.gz.sha256` files) or `brew install`
# will fail.

class Logr < Formula
  desc "Security log analyzer — detect threats, score risks, and audit logs from the terminal"
  homepage "https://github.com/senaraufi/Security-Log-Analyser"
  version "1.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/senaraufi/Security-Log-Analyser/releases/download/v#{version}/logr-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_DARWIN_SHA256"
    end
    on_intel do
      url "https://github.com/senaraufi/Security-Log-Analyser/releases/download/v#{version}/logr-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_X86_64_DARWIN_SHA256"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/senaraufi/Security-Log-Analyser/releases/download/v#{version}/logr-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_X86_64_LINUX_SHA256"
    end
  end

  def install
    bin.install "logr"
  end

  test do
    assert_match "logr", shell_output("#{bin}/logr --help")
  end
end
