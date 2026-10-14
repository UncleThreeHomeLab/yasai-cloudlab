"""Bounded traces and metrics; request secrets and exception details never export."""
from contextlib import contextmanager, nullcontext
import json
import os
import re
import time

TRACER = None
REQUESTS = None
DURATION = None
PROPAGATOR = None
REVISION = None
ROUTES = {'/', '/health', '/ready', '/live', '/api/notes', '/api/release/notes', '/api/operations'}


def start(service):
    global TRACER, REQUESTS, DURATION, PROPAGATOR, REVISION
    if os.environ.get('OTEL_ENABLED') != '1': return
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from prometheus_client import Counter, Histogram, start_http_server
    if service not in ('notes-web', 'notes-api'):
        raise ValueError('Unexpected telemetry service')
    endpoint = os.environ['OTEL_EXPORTER_OTLP_TRACES_ENDPOINT']
    if endpoint != 'http://cloudlab-alloy.cloudlab-observability.svc:4318/v1/traces':
        raise ValueError('Telemetry must use the local approved collector')
    REVISION = os.environ.get('SOURCE_SHA256', '')
    if not re.fullmatch('[a-f0-9]{64}', REVISION):
        raise ValueError('Telemetry requires its immutable source revision')
    provider = TracerProvider(resource=Resource({'service.name': service}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, timeout=2),
        max_queue_size=256, max_export_batch_size=64, schedule_delay_millis=1000, export_timeout_millis=2000))
    TRACER = provider.get_tracer('cloudlab.notes')
    PROPAGATOR = TraceContextTextMapPropagator()
    labels = ('service', 'route', 'method', 'status', 'traffic', 'revision')
    REQUESTS = Counter('cloudlab_http_requests', 'Completed bounded application requests', labels)
    DURATION = Histogram('cloudlab_http_duration_seconds', 'Application response duration', labels,
                         buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10))
    start_http_server(9091)


def headers():
    if TRACER is None: return {}
    from opentelemetry import trace
    # One propagator owns both extraction and injection; no user baggage or headers.
    result = {}
    PROPAGATOR.inject(result, context=trace.set_span_in_context(trace.get_current_span()))
    return {key: value for key, value in result.items() if key == 'traceparent'}


def dependency(name):
    if name not in ('database', 'objects'): raise ValueError('Unexpected dependency span')
    return nullcontext() if TRACER is None else TRACER.start_as_current_span('notes.' + name,
        record_exception=False, set_status_on_exception=False)


@contextmanager
def request(handler, service):
    route = handler.path.split('?', 1)[0]
    route = route if route in ROUTES else 'other'
    traffic = 'release' if route == '/api/release/notes' else ('synthetic' if route in ('/health', '/ready', '/live') else 'user')
    handler.telemetry_status = 500
    started = time.monotonic()
    context = None
    if PROPAGATOR:
        context = PROPAGATOR.extract({'traceparent': handler.headers.get('traceparent', '')})
    span = nullcontext(None) if TRACER is None else TRACER.start_as_current_span('notes.' + service.split('-')[1],
        context=context, attributes={'http.route': route, 'http.request.method': handler.command,
                                     'cloudlab.traffic': traffic}, record_exception=False, set_status_on_exception=False)
    with span as current:
        try:
            yield
        finally:
            if current:
                from opentelemetry.trace import Status, StatusCode
                status = handler.telemetry_status
                current.set_attribute('http.response.status_code', status)
                if status >= 500: current.set_status(Status(StatusCode.ERROR))
                elapsed = max(0, time.monotonic() - started)
                labels = (service, route, handler.command, str(status), traffic, REVISION)
                exemplar = {'trace_id': format(current.get_span_context().trace_id, '032x')}
                REQUESTS.labels(*labels).inc(exemplar=exemplar)
                DURATION.labels(*labels).observe(elapsed, exemplar=exemplar)
                print(json.dumps({'kind': 'request', 'service': service, 'route': route, 'status': status,
                                  'duration_ms': round(elapsed * 1000, 3), **exemplar}, separators=(',', ':')), flush=True)


def instrument(handler, service):
    for method in ('GET', 'POST'):
        original = getattr(handler, 'do_' + method, None)
        if original is None: continue
        def wrapped(self, original=original):
            with request(self, service): return original(self)
        setattr(handler, 'do_' + method, wrapped)
    original_response = handler.send_response
    def response(self, status, *args, **kwargs):
        self.telemetry_status = status
        return original_response(self, status, *args, **kwargs)
    handler.send_response = response
