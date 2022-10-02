# Maintainer: Erik "Nuckal777" Schubert <nuckal777+nicator@gmail.com>
pkgname=nicator
pkgver=0.3.0
pkgrel=1
pkgdesc="A lightweight encrypting git credential helper"
arch=('x86_64')
url="https://github.com/Nuckal777/nicator"
license=('Unlicense')
depends=('gcc-libs')
makedepends=('cargo' 'git')
optdepends=('git: the VCS nicator is made for')
source=("$pkgname"::"git+https://github.com/Nuckal777/nicator#tag=v0.3.0")
noextract=()
md5sums=('SKIP')

check() {
    cd "$pkgname"
    RUSTUP_TOOLCHAIN=stable cargo test --release --locked --target-dir=target
}

build() {
    cd "$pkgname"
    RUSTUP_TOOLCHAIN=stable cargo build --release --locked --all-features --target-dir=target
}

package() {
    cd "$pkgname"
    install -Dm 755 target/release/${pkgname} -t "${pkgdir}/usr/bin"
}
