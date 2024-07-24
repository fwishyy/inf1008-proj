"""
This module processes the APT group and operation data from the open-source STIX data and the APT group and operation database.
"""

import pandas as pd
import spacy

from attackcti import attack_client

DATABASE_NAME = 'apt_groups_and_operations.xlsx'
DATABASE_SHEETS = ['China', 'Russia', 'North Korea', 'Iran', 'Israel', 'NATO', 'Middle East', 'Others', 'Unknown']

def load_from_excel(sheet_name=''):
    data = pd.read_excel(DATABASE_NAME, sheet_name=sheet_name, skiprows=1)
    return data

# get groups from open-source STIX data
def query_groups():
    lift = attack_client()
    group_query = lift.get_enterprise_groups(stix_format=True)
    
    print(f'Total number of groups: {len(group_query)}')

    groups = pd.DataFrame(columns=['apt_name', 'description', 'aliases', 'malware'])
    i = 0
    for group in group_query:
        apt_name = normalize_string(group.name)
        aliases = [normalize_string(alias) for alias in group.aliases]

        # get list of known malware used by group
        malware_query = lift.get_software_used_by_group(group, stix_format=True)

        malware= []
        for mw in malware_query:
            malware.append(normalize_string(mw.name))

        groups = groups._append({'apt_name': apt_name, 'description': group['description'], 'aliases': aliases, 'malware': malware}, ignore_index=True)
        
        i += 1
        
        print(f'{i} [{apt_name}, {aliases}, {malware}]')
    
    return groups

# extract targeted countries from APT operation descriptions
def get_countries_from_target(nlp, targets):
    doc = nlp(targets)
    countries = set()
    for ent in doc.ents:
        if ent.label_ == 'GPE':
            countries.add(ent.text)
    return countries

def normalize_string(s):
    return s.strip().replace(' ', '')

def main():
    # get group info
    try:
        with open('apt_info.json', 'r') as f:
            groups = pd.read_json(f)
    except FileNotFoundError:
        groups = query_groups()
        groups.to_json('apt_info.json', orient='records')

    apt_aliases = {}

    for _, group in groups.iterrows():
        apt_aliases[group.get('apt_name')] = group.get('aliases')
        # fast lookup, store aliases not just for name but for all aliases
        for alias in group.get('aliases'):
            apt_aliases[alias] = group.get('aliases')
                       
    nlp = spacy.load('en_core_web_sm')

    output_df = pd.DataFrame(columns=['apt_name', 'aliases', 'targets'])
    
    for sheet_name in DATABASE_SHEETS:
        data = load_from_excel(sheet_name)

        # extract list of targeted countries from the 'Targets' column
        for _, row in data.iterrows():
            if str(row['Targets']) != 'nan':
                countries_targeted = get_countries_from_target(nlp, row['Targets'])

                # TODO: Clean up countries targeted

                if countries_targeted:
                    apt_name = normalize_string(row['Common Name'])
                    aliases = apt_aliases.get(apt_name, [])
                    output_df = output_df._append({'apt_name': apt_name, 'aliases': aliases, 'targets': countries_targeted}, ignore_index=True)

    output_df.to_json('apt_targets.json', orient='records')

if __name__ == '__main__':
    main()