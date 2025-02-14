#  Generated from FHIR 4.0.1-9346c8cc45, SMART Health IT.

import os
import io
import unittest
import json
from fhirclient.models import molecularsequence
from fhirclient.models.fhirdate import FHIRDate
from fhirclient.models.fhirdatetime import FHIRDateTime
from fhirclient.models.fhirinstant import FHIRInstant
from fhirclient.models.fhirtime import FHIRTime


class MolecularSequenceTests(unittest.TestCase):
    def instantiate_from(self, filename):
        datadir = os.path.join(os.path.dirname(__file__), '..', 'data', 'examples')
        with io.open(os.path.join(datadir, filename), 'r', encoding='utf-8') as handle:
            js = json.load(handle)
            self.assertEqual("MolecularSequence", js["resourceType"])
        return molecularsequence.MolecularSequence(js)
    
    def testMolecularSequence1(self):
        inst = self.instantiate_from("sequence-graphic-example-2.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence1(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence1(inst2)
    
    def implMolecularSequence1(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "graphic-example-2")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.referenceSeqString, "CGCCATTG")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 8)
        self.assertEqual(inst.referenceSeq.windowStart, 0)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
    
    def testMolecularSequence2(self):
        inst = self.instantiate_from("sequence-genetics-example-breastcancer.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence2(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence2(inst2)
    
    def implMolecularSequence2(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "breastcancer")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NM_000059.3")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].display, "Homo sapiens BRCA2, DNA repair associated (BRCA2), mRNA")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore/")
        self.assertEqual(inst.referenceSeq.windowEnd, 101499444)
        self.assertEqual(inst.referenceSeq.windowStart, 101488058)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "rna")
        self.assertEqual(inst.variant[0].end, 32316187)
        self.assertEqual(inst.variant[0].observedAllele, "A")
        self.assertEqual(inst.variant[0].referenceAllele, "C")
        self.assertEqual(inst.variant[0].start, 32316186)
    
    def testMolecularSequence3(self):
        inst = self.instantiate_from("sequence-graphic-example-5.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence3(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence3(inst2)
    
    def implMolecularSequence3(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "graphic-example-5")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NC_000002.12")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 128273736)
        self.assertEqual(inst.referenceSeq.windowStart, 128273732)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
    
    def testMolecularSequence4(self):
        inst = self.instantiate_from("sequence-graphic-example-3.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence4(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence4(inst2)
    
    def implMolecularSequence4(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "graphic-example-3")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 128273736)
        self.assertEqual(inst.referenceSeq.windowStart, 128273732)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].cigar, "2M")
        self.assertEqual(inst.variant[0].end, 128273736)
        self.assertEqual(inst.variant[0].observedAllele, "GA")
        self.assertEqual(inst.variant[0].referenceAllele, "AT")
        self.assertEqual(inst.variant[0].start, 1282737234)
    
    def testMolecularSequence5(self):
        inst = self.instantiate_from("coord-1base-example.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence5(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence5(inst2)
    
    def implMolecularSequence5(self, inst):
        self.assertEqual(inst.coordinateSystem, 1)
        self.assertEqual(inst.id, "coord-1-base")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.observedSeq, "ACATGGTAGC")
        self.assertEqual(inst.referenceSeq.referenceSeqString, "ACGTAGTC")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 8)
        self.assertEqual(inst.referenceSeq.windowStart, 1)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].cigar, "3I")
        self.assertEqual(inst.variant[0].end, 3)
        self.assertEqual(inst.variant[0].observedAllele, "ATG")
        self.assertEqual(inst.variant[0].referenceAllele, "-")
        self.assertEqual(inst.variant[0].start, 2)
        self.assertEqual(inst.variant[1].cigar, "3I")
        self.assertEqual(inst.variant[1].end, 5)
        self.assertEqual(inst.variant[1].observedAllele, "T")
        self.assertEqual(inst.variant[1].referenceAllele, "A")
        self.assertEqual(inst.variant[1].start, 5)
        self.assertEqual(inst.variant[2].cigar, "1D")
        self.assertEqual(inst.variant[2].end, 7)
        self.assertEqual(inst.variant[2].observedAllele, "-")
        self.assertEqual(inst.variant[2].referenceAllele, "T")
        self.assertEqual(inst.variant[2].start, 7)
    
    def testMolecularSequence6(self):
        inst = self.instantiate_from("sequence-graphic-example-4.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence6(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence6(inst2)
    
    def implMolecularSequence6(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "graphic-example-4")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.chromosome.coding[0].code, "2")
        self.assertEqual(inst.referenceSeq.chromosome.coding[0].display, "chromosome 2")
        self.assertEqual(inst.referenceSeq.chromosome.coding[0].system, "http://terminology.hl7.org/CodeSystem/chromosome-human")
        self.assertEqual(inst.referenceSeq.genomeBuild, "GRCh 38")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 128273740)
        self.assertEqual(inst.referenceSeq.windowStart, 128273736)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
    
    def testMolecularSequence7(self):
        inst = self.instantiate_from("sequence-example-TPMT-one.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence7(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence7(inst2)
    
    def implMolecularSequence7(self, inst):
        self.assertEqual(inst.coordinateSystem, 1)
        self.assertEqual(inst.id, "example-TPMT-one")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.observedSeq, "T-C-C-C-A-C-C-C")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NT_007592.15")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 18143955)
        self.assertEqual(inst.referenceSeq.windowStart, 18130918)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].end, 18139214)
        self.assertEqual(inst.variant[0].observedAllele, "A")
        self.assertEqual(inst.variant[0].referenceAllele, "G")
        self.assertEqual(inst.variant[0].start, 18139214)
    
    def testMolecularSequence8(self):
        inst = self.instantiate_from("sequence-graphic-example-1.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence8(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence8(inst2)
    
    def implMolecularSequence8(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "graphic-example-1")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NC_000002.12")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 128273732)
        self.assertEqual(inst.referenceSeq.windowStart, 128273724)
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].cigar, "1M")
        self.assertEqual(inst.variant[0].end, 128273726)
        self.assertEqual(inst.variant[0].observedAllele, "G")
        self.assertEqual(inst.variant[0].referenceAllele, "T")
        self.assertEqual(inst.variant[0].start, 128273725)
    
    def testMolecularSequence9(self):
        inst = self.instantiate_from("sequence-example-fda.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence9(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence9(inst2)
    
    def implMolecularSequence9(self, inst):
        self.assertEqual(inst.coordinateSystem, 1)
        self.assertEqual(inst.id, "fda-example")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.quality[0].end, 101770080)
        self.assertEqual(inst.quality[0].fScore, 0.545551)
        self.assertEqual(inst.quality[0].gtFP, 2186)
        self.assertEqual(inst.quality[0].method.coding[0].code, "job-ByxYPx809jFVy21KJG74Jg3Y")
        self.assertEqual(inst.quality[0].method.coding[0].system, "https://precision.fda.gov/jobs/")
        self.assertEqual(inst.quality[0].method.text, "Vcfeval + Hap.py Comparison")
        self.assertEqual(inst.quality[0].precision, 0.428005)
        self.assertEqual(inst.quality[0].queryFP, 10670)
        self.assertEqual(inst.quality[0].queryTP, 7984)
        self.assertEqual(inst.quality[0].recall, 0.752111)
        self.assertEqual(inst.quality[0].standardSequence.coding[0].code, "file-Bk50V4Q0qVb65P0v2VPbfYPZ")
        self.assertEqual(inst.quality[0].standardSequence.coding[0].system, "https://precision.fda.gov/files/")
        self.assertEqual(inst.quality[0].start, 10453)
        self.assertEqual(inst.quality[0].truthFN, 2554)
        self.assertEqual(inst.quality[0].truthTP, 7749)
        self.assertEqual(inst.quality[0].type, "snp")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NC_000001.11")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 101770080)
        self.assertEqual(inst.referenceSeq.windowStart, 10453)
        self.assertEqual(inst.repository[0].name, "FDA")
        self.assertEqual(inst.repository[0].type, "login")
        self.assertEqual(inst.repository[0].url, "https://precision.fda.gov/files/file-Bx37ZK009P4bX5g3qjkFZV38")
        self.assertEqual(inst.repository[0].variantsetId, "file-Bx37ZK009P4bX5g3qjkFZV38")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].end, 13117)
        self.assertEqual(inst.variant[0].observedAllele, "T")
        self.assertEqual(inst.variant[0].referenceAllele, "G")
        self.assertEqual(inst.variant[0].start, 13116)
    
    def testMolecularSequence10(self):
        inst = self.instantiate_from("molecularsequence-example.json")
        self.assertIsNotNone(inst, "Must have instantiated a MolecularSequence instance")
        self.implMolecularSequence10(inst)
        
        js = inst.as_json()
        self.assertEqual("MolecularSequence", js["resourceType"])
        inst2 = molecularsequence.MolecularSequence(js)
        self.implMolecularSequence10(inst2)
    
    def implMolecularSequence10(self, inst):
        self.assertEqual(inst.coordinateSystem, 0)
        self.assertEqual(inst.id, "example")
        self.assertEqual(inst.meta.tag[0].code, "HTEST")
        self.assertEqual(inst.meta.tag[0].display, "test health data")
        self.assertEqual(inst.meta.tag[0].system, "http://terminology.hl7.org/CodeSystem/v3-ActReason")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].code, "NC_000009.11")
        self.assertEqual(inst.referenceSeq.referenceSeqId.coding[0].system, "http://www.ncbi.nlm.nih.gov/nuccore")
        self.assertEqual(inst.referenceSeq.strand, "watson")
        self.assertEqual(inst.referenceSeq.windowEnd, 22125510)
        self.assertEqual(inst.referenceSeq.windowStart, 22125500)
        self.assertEqual(inst.repository[0].name, "GA4GH API")
        self.assertEqual(inst.repository[0].type, "openapi")
        self.assertEqual(inst.repository[0].url, "http://grch37.rest.ensembl.org/ga4gh/variants/3:rs1333049?content-type=application/json")
        self.assertEqual(inst.repository[0].variantsetId, "3:rs1333049")
        self.assertEqual(inst.text.status, "generated")
        self.assertEqual(inst.type, "dna")
        self.assertEqual(inst.variant[0].end, 22125504)
        self.assertEqual(inst.variant[0].observedAllele, "C")
        self.assertEqual(inst.variant[0].referenceAllele, "G")
        self.assertEqual(inst.variant[0].start, 22125503)

