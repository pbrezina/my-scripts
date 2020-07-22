def html_quote(value):
    return value.replace('"', '&quot;')


class FilterModule(object):
    def filters(self):
        return {
            'html_quote': html_quote
        }
