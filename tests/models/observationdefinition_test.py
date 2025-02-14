#  Generated from FHIR 4.0.1-9346c8cc45, SMART Health IT.

import os
import io
import unittest
import json
from fhirclient.models import observationdefinition
from fhirclient.models.fhirdate import FHIRDate
from fhirclient.models.fhirdatetime import FHIRDateTime
from fhirclient.models.fhirinstant import FHIRInstant
from fhirclient.models.fhirtime import FHIRTime


class ObservationDefinitionTests(unittest.TestCase):
    def instantiate_from(self, filename):
        datadir = os.path.join(os.path.dirname(__file__), '..', 'data', 'examples')
        with io.open(os.path.join(datadir, filename), 'r', encoding='utf-8') as handle:
            js = json.load(handle)
            self.assertEqual("ObservationDefinition", js["resourceType"])
        return observationdefinition.ObservationDefinition(js)
    
    def testObservationDefinition1(self):
        inst = self.instantiate_from("observationdefinition-example.json")
        self.assertIsNotNone(inst, "Must have instantiated a ObservationDefinition instance")
        self.implObservationDefinition1(inst)
        
        js = inst.as_json()
        self.assertEqual("ObservationDefinition", js["resourceType"])
        inst2 = observationdefinition.ObservationDefinition(js)
        self.implObservationDefinition1(inst2)
    
    def implObservationDefinition1(self, inst):
        self.assertEqual(inst.code.coding[0].code, "15074-8")
        self.assertEqual(inst.code.coding[0].display, "Glucose [Moles/volume] in Blood")
        self.assertEqual(inst.code.coding[0].system, "http://loinc.org")
        self.assertEqual(inst.id, "example")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.text.status, "generated")

