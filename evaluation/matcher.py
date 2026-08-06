from evaluation.labels import normalize_label, parse_binary_label


def normalize(value):
    return normalize_label(value).replace("-", " ")


def empty_like(value):
    value = normalize(value)
    return value in ["", "none", "n/a", "na", "not found", "unknown", "nan"]


def match_text(expected, actual):
    expected = normalize(expected)
    actual = normalize(actual)

    if empty_like(expected):
        return empty_like(actual)
    if empty_like(actual):
        return False
    return expected in actual or actual in expected


def match_cve(expected, actual):
    expected = normalize(expected)
    actual = normalize(actual)

    if empty_like(expected):
        return empty_like(actual)
    if empty_like(actual):
        return False
    return expected in actual


def match_vulnerable(expected, actual):
    expected_label = parse_binary_label(expected, "vulnerability")
    actual_label = parse_binary_label(actual, "vulnerability")
    return (
        expected_label is not None
        and actual_label is not None
        and expected_label == actual_label
    )


def match_success(expected, actual_success):
    expected_label = parse_binary_label(expected, "success")
    actual_label = parse_binary_label(actual_success, "success")
    return (
        expected_label is not None
        and actual_label is not None
        and expected_label == actual_label
    )
