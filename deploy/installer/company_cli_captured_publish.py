"""One-use preparation coupling actual protected captures to original publisher.

The company independently authenticates all executing module/caller origins.
This helper does not execute a CLI, publish bytes, select native adapters, close
borrowed IO, issue evidence or ACK. It never accepts caller-supplied byte fields.
"""
import hashlib
from types import FunctionType, MappingProxyType, ModuleType

UNRELEASED = []
COLLABORATORS = ('files', 'crypto', 'backend_module', 'backend', 'runner_module',
                 'runner', 'parent_system_module', 'parent_system', 'clock')


class CapturedPublishUnavailable(ValueError):
    pass


def _factory(public, exception):
    used, failed = False, False
    retained = []
    fields = COLLABORATORS
    module_kind, function_kind, proxy = ModuleType, FunctionType, MappingProxyType
    raw_sha = hashlib.sha256

    def need(value):
        if value is not True:
            raise exception('company-cli-captured-publish-unavailable')

    def capture(module):
        need(type(module) is module_kind)
        namespace = dict(vars(module))
        need(len(namespace) <= 512 and all(type(key) is str for key in namespace))
        name = namespace.get('__name__')
        need(type(name) is str)
        classes = []
        for item in namespace.values():
            if type(item) is type:
                owner = type.__getattribute__(item, '__module__')
                need(type(owner) is str)
                if owner == name:
                    table = tuple(vars(item).items())
                    need(len(table) <= 128 and all(type(key) is str for key, value in table))
                    classes.append((item, table))
        return (module, tuple(namespace.items()), tuple(classes))

    def guard(rows):
        for module, namespace, classes in rows:
            current = dict(vars(module))
            need(all(type(key) is str for key in current) and len(current) == len(namespace)
                 and all(key in current and current[key] is value for key, value in namespace))
            for kind, table in classes:
                current = dict(vars(kind))
                need(all(type(key) is str for key in current) and len(current) == len(table)
                     and all(key in current and current[key] is value for key, value in table))

    def function(module, name):
        value = vars(module).get(name)
        need(type(value) is function_kind and value.__globals__ is vars(module))
        return value

    def prepare_captured_publish(cli_module, record_reader_module, publisher_module, *, io_module, io, collaborators):
        """Use the saved original IO property; no execution or ownership transfer.

        The IO instance remains borrowed and must outlive the returned original
        publisher. Its private issuance, endpoint/copy graph and full unrelated
        input coverage remain obligations of the original IO/company caller.
        Pure structural denial before callbacks does not consume this helper;
        the first admitted call is consumed before its original IO validator.
        """
        nonlocal used, failed
        need(not used and not failed and not retained and type(public) is list and not public)
        need(type(collaborators) is dict and all(type(key) is str for key in collaborators)
             and set(collaborators) == set(fields))
        refs = tuple((name, collaborators[name]) for name in fields)
        rows = tuple(capture(module) for module in (cli_module, record_reader_module, publisher_module, io_module))
        rows += tuple(capture(dict(refs)[name]) for name in ('backend_module', 'runner_module', 'parent_system_module'))
        io_kind = vars(io_module).get('PublisherIO')
        publisher_kind = vars(publisher_module).get('RecordPublisher')
        need(type(io_kind) is type and type(io) is io_kind and type(publisher_kind) is type)
        getter = vars(io_kind).get('captured_inputs')
        need(type(getter) is property and type(getter.fget) is function_kind
             and getter.fget.__globals__ is vars(io_module))
        validator = function(io_module, 'require_publisher_io')
        prepare = function(publisher_module, 'prepare_publish')
        guard(rows)
        used = True
        actual = publisher = arguments = None
        try:
            need(validator(io) is io)
            guard(rows)
            actual = getter.fget(io)  # Preserve exact returned mapping before postguard.
            guard(rows)
            need(type(actual) is proxy and all(type(key) is str for key in actual)
                 and set(actual) == {'request_raw', 'invocation_raw', 'plan_raw'})
            for name, maximum in (('request_raw', 4096), ('invocation_raw', 4096), ('plan_raw', 16384)):
                need(type(actual[name]) is bytes and 0 < len(actual[name]) <= maximum)
            arguments = dict(refs)
            arguments.update(request_raw=actual['request_raw'], request_sha256=raw_sha(actual['request_raw']).hexdigest(),
                invocation_raw=actual['invocation_raw'], invocation_sha256=raw_sha(actual['invocation_raw']).hexdigest(),
                plan_raw=actual['plan_raw'])
            guard(rows)
            publisher = prepare(cli_module, record_reader_module, dispatch_arguments=arguments, io_module=io_module, io=io)
            guard(rows)
            need(type(publisher) is publisher_kind and validator(io) is io)
            guard(rows)
            return publisher
        except BaseException as problem:
            failed = True
            item = (rows, refs, io, getter, validator, prepare, actual, arguments, publisher, problem)
            retained.append(item)
            public.append(item)
            raise exception('company-cli-captured-publish-unavailable') from None

    return prepare_captured_publish


prepare_captured_publish = _factory(UNRELEASED, CapturedPublishUnavailable)
del _factory


def main(argv=None):
    raise CapturedPublishUnavailable('company-cli-captured-publish-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
