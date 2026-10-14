# Supplied PDF provenance and reference inventory

## Source and verification

The source is `/home/radhey/Downloads/patent.pdf`. The supplied PDF has 31 pages and is 595,967 bytes. Its SHA-256 digest is `f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771`.

A second read on 14 October 2026 reproduced the same digest, byte count, and page inventory. The printed page numbers run from 1 through 31 and match the corresponding PDF page numbers.

Recheck the file with:

```sh
sha256sum /home/radhey/Downloads/patent.pdf
pdfinfo /home/radhey/Downloads/patent.pdf | grep -E '^(Pages|File size):'
pdftotext -layout /home/radhey/Downloads/patent.pdf -
pdftotext -bbox-layout /home/radhey/Downloads/patent.pdf -
```

The text extraction exposes paragraph and claim labels page by page. The bounding-box extraction includes printed footer labels. Render the two drawing pages to inspect the figures:

```sh
pdftoppm -f 30 -l 31 -png /home/radhey/Downloads/patent.pdf /tmp/patent-page
```

## Page inventory

The first number in each page reference is the PDF page. The second is the printed page. They match on all 31 pages. Paragraph labels below are transcribed as printed. A continuation entry identifies a paragraph that crosses a page break. The source prints paragraph labels [00100]–[00110] with five digits; these labels are retained verbatim.

| PDF page / printed page | Contents |
| --- | --- |
| 1 / 1 | Form 2 title, applicant details, and preamble to the description. |
| 2 / 2 | Paragraphs [0001]–[0006]. |
| 3 / 3 | Paragraphs [0007]–[0016]. |
| 4 / 4 | Paragraphs [0017]–[0026]. |
| 5 / 5 | Paragraphs [0027]–[0028] begin. |
| 6 / 6 | Paragraph [0028] continues; paragraphs [0029]–[0034] begin. Paragraph [0034] continues on page 7. |
| 7 / 7 | Paragraph [0034] continues; paragraphs [0035]–[0040]. |
| 8 / 8 | Paragraphs [0041]–[0043] begin. Paragraph [0043] continues on page 9. |
| 9 / 9 | Paragraph [0043] continues; paragraphs [0044]–[0050] begin. Paragraph [0050] continues on page 10. |
| 10 / 10 | Paragraph [0050] continues; paragraphs [0051]–[0053] begin. Paragraph [0053] continues on page 11. |
| 11 / 11 | Paragraph [0053] continues; paragraphs [0054]–[0056] begin. Paragraph [0056] continues on page 12. |
| 12 / 12 | Paragraph [0056] continues; paragraph [0057] begins and continues on page 13. |
| 13 / 13 | Paragraph [0057] continues; paragraphs [0058]–[0059]. |
| 14 / 14 | Paragraphs [0060]–[0063] begin. Paragraph [0063] continues on page 15. |
| 15 / 15 | Paragraph [0063] continues; paragraphs [0064]–[0066] begin. Paragraph [0066] continues on page 16. |
| 16 / 16 | Paragraph [0066] continues; paragraphs [0067]–[0068]. |
| 17 / 17 | Paragraphs [0069]–[0071]. |
| 18 / 18 | Paragraphs [0072]–[0074]. |
| 19 / 19 | Paragraphs [0075]–[0079] begin. Paragraph [0079] continues on page 20. |
| 20 / 20 | Paragraph [0079] continues; paragraphs [0080]–[0082]. |
| 21 / 21 | Paragraphs [0083]–[0085] begin. Paragraph [0085] continues on page 22. |
| 22 / 22 | Paragraph [0085] continues; paragraphs [0086]–[0089] begin. Paragraph [0089] continues on page 23. |
| 23 / 23 | Paragraph [0089] continues; paragraphs [0090]–[0092]. |
| 24 / 24 | Paragraphs [0093]–[0099], [00100], and [00101]. |
| 25 / 25 | Paragraphs [00102]–[00110]. |
| 26 / 26 | Claim 1; claim 2 begins and continues on page 27. |
| 27 / 27 | Claim 2 continues; claims 3–7; claim 8 begins and continues on page 28. |
| 28 / 28 | Claim 8 continues; claim 9; claim 10 begins and continues on page 29. |
| 29 / 29 | Claim 10 continues; signature block dated 12th June, 2025. |
| 30 / 30 | Abstract and drawing labelled FIG. 1. |
| 31 / 31 | Drawing labelled FIG. 2. |

## Claim index

| Printed claim | PDF page(s) | Printed page(s) |
| --- | --- | --- |
| 1 | 26 | 26 |
| 2 | 26–27 | 26–27 |
| 3 | 27 | 27 |
| 4 | 27 | 27 |
| 5 | 27 | 27 |
| 6 | 27 | 27 |
| 7 | 27 | 27 |
| 8 | 27–28 | 27–28 |
| 9 | 28 | 28 |
| 10 | 28–29 | 28–29 |

## Figure inventory

| Figure | Text references | Drawing in supplied PDF |
| --- | --- | --- |
| FIG. 1 | Described in paragraph [0037] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0050] on page 9. | Present on PDF page 30, printed page 30. |
| FIG. 2 | Described in paragraph [0038] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0074] on page 18. | Present on PDF page 31, printed page 31. |
| FIG. 3 | Described in paragraph [0039] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraph [0080] on page 20. | No drawing appears in the supplied 31-page PDF. The specification contains text references only. |
| FIG. 4 | Described in paragraph [0040] on PDF and printed page 7; referenced in paragraph [0049] on page 9 and paragraphs [0088]–[0089] on pages 22–23. | No drawing appears in the supplied 31-page PDF. The specification contains text references only. |

## Date and legal-status limits

The signature block on PDF page 29, printed page 29, says `Dated: 12th June, 2025`. This is the date printed with the patent agent's signature. This inventory does not verify a filing date, publication date, grant status, or legal coverage, and it is not a legal opinion.
