from vaultknox.branding import get_logo_asset_path, get_logo_banner, get_logo_png_path


def test_logo_banner_contains_product_name() -> None:
    banner = get_logo_banner()
    assert "Secure Secret Add-On" in banner


def test_logo_asset_path_points_to_svg() -> None:
    logo_path = get_logo_asset_path()
    assert logo_path.name == "vaultknox-logo.svg"
    assert logo_path.exists()


def test_logo_png_path_exists() -> None:
    logo_path = get_logo_png_path()
    assert logo_path.name == "vaultknox-logo.png"
    assert logo_path.exists()
