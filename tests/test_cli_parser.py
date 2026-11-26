from core.cli_parser import parse_arguments


def test_parse_arguments_all_enables_modules():
    args = parse_arguments(["example.com", "--all"])

    assert args.domain_pos == "example.com"
    assert args.all is True


def test_parse_arguments_geo_and_score_flags():
    args = parse_arguments(["-d", "example.com", "--geo", "--score"])

    assert args.domain_opt == "example.com"
    assert args.geolocation is True
    assert args.security_score is True
