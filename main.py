import json
import networkx as nx
import matplotlib.pyplot as plt
from attackcti import attack_client
from IOC import IOC

# hardcoded for now
DATABASE_NAME = 'data.json'

IOC_TABLE = {}

def load_from_json(filename):
    with open(filename, 'r') as f:
        data_json = json.load(f)
    return data_json

def normalize_string(s):
    return s.strip().replace(' ', '')

def degree_centrality_analysis(G):
    degree_centrality = nx.degree_centrality(G)

    # sort by degree centrality
    sorted_degree_centrality = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)

    return sorted_degree_centrality[:5]
    
def main():
    data_json = load_from_json(DATABASE_NAME)
    apt_targets_json = load_from_json('apt_targets.json')
    
    # lookup table for apt aliases
    apt_lookup = {}

    # convert from apt_targets_json to a dictionary
    apt_targets = {}
    for entry in apt_targets_json:
        apt_targets[entry.get('apt_name')] = entry.get('targets')
        apt_lookup[entry.get('apt_name')] = entry.get('apt_name')
        for alias in entry.get('aliases'):
            apt_lookup[alias] = entry.get('apt_name')

    # create a knowledge graph
    G = nx.DiGraph()
    for entry in data_json:

        # each entry can have different types of IOCs: hash, ip, domains
        sha256_hashes = entry.get('sha256_hashes', [])
        md5_hashes = entry.get('md5_hashes', [])
        ip_addresses = entry.get('ips', [])

        iocs = []

        for hash in sha256_hashes:
            ioc = IOC(name=hash, type='sha256 hash', created_date=entry.get('created_time'))
            IOC_TABLE[ioc.name] = ioc
            iocs.append(ioc)
        
        for hash in md5_hashes:
            ioc = IOC(name=hash, type='md5 hash', created_date=entry.get('created_time'))
            IOC_TABLE[ioc.name] = ioc
            iocs.append(ioc)
        
        for ip in ip_addresses:
            ioc = IOC(name=ip, type='ip address', created_date=entry.get('created_time'))
            IOC_TABLE[ioc.name] = ioc
            iocs.append(ioc)

        for idx, ioc in enumerate(iocs):
            # associate tags with only the first IOC to reduce clutter
            if idx == 0:
                for tag in entry.get('tags'):
                    # add edge between ioc and tag
                    G.add_edge(ioc.name, tag)
                    if tag in apt_lookup:
                        # resolve common name for aliases
                        apt_common_name = apt_lookup[tag]
                        for country in apt_targets[apt_common_name]:
                            # establish relationship between APT and countries targeted
                            G.add_edge(tag, country, label='targets')
            # associate the rest of the IOCs with the first IOC
            else:
                # add edge between ioc and previous ioc
                G.add_edge(iocs[0].name, ioc.name)

    print(f'Number of IOC entries: {len(IOC_TABLE)}')

    highlighted_nodes = degree_centrality_analysis(G)
    print(f'Importtant nodes: {highlighted_nodes}')

    # visualize graph with labels
    pos = nx.spring_layout(G, k=0.5, scale=2)
    nx.draw(G, pos, with_labels=True, node_size=100, font_size=8, font_color='black')
    # draw edges with labels
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    
    plt.show()

if __name__ == '__main__':
    main()