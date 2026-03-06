from wordlist_registry import WordlistRegistry


def test_register_and_remove_wordlist(tmp_path):
    registry = WordlistRegistry(str(tmp_path / "wordlists.json"))
    wl_path = tmp_path / "small.txt"
    wl_path.write_text("admin\nroot\n", encoding="utf-8")

    created = registry.register_wordlist("common", str(wl_path), "small test list")
    assert created["name"] == "common"
    assert created["size_bytes"] > 0

    all_items = registry.list_wordlists()
    assert len(all_items) == 1
    assert all_items[0]["name"] == "common"

    removed = registry.remove_wordlist("common")
    assert removed is not None
    assert registry.list_wordlists() == []
