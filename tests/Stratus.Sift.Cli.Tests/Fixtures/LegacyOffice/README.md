# Legacy PowerPoint fixture

`basic_test_ppt_file.ppt` comes from Apache POI's `test-data/slideshow` directory:
https://github.com/apache/poi/blob/trunk/test-data/slideshow/basic_test_ppt_file.ppt

The expected slide text is independently specified in Apache POI's
`poi-scratchpad/src/test/java/org/apache/poi/hslf/extractor/TestExtractor.java`:
https://github.com/apache/poi/blob/trunk/poi-scratchpad/src/test/java/org/apache/poi/hslf/extractor/TestExtractor.java

The fixture tests slide text stored in the central `SlideListWithText` records,
which differs from the Escher text-box storage used by generated fixtures.
Apache POI's licence and notices are included alongside this file.
