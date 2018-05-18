
def return_decoded_value(value):
    if type(value) is bytes:
        value = value.decode('utf-8')
    elif type(value) is not str:
        value = value.decode("ascii", "ignore")
    else:
        value = value

    return value.strip('\r\n')
