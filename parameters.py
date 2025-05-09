from configparser import ConfigParser
 
 
def read_param(filename, section):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)
 
    # get section, default to postgresql
    outval = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            outval[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))
 
    return outval