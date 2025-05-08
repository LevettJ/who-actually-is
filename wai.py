import argparse

# WHOactuallyIS package
import whoactuallyis

# import keys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='WHOactuallyIS: find the owners and users of Internet resources.'
    )
    parser.add_argument('-t', '--target',
                        help='Target resource',
                        required=False)
    args = parser.parse_args()

    if args.target is not None:
        # whoactuallyis.Keys['companies-house'] = keys.COMPANIES_HOUSE
        r = whoactuallyis.lookup(args.target)
        whoactuallyis.show_final_name(r)
