package gocircuitexternal

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

const (
	treeLevel = 10
)

var template = []leaf{
	newleaf("4809579517396073186705705159186899409599314609122482090560534255195823961763", "2038038677412689124034084719683107814279606773706261227437666149072023632255"),  // credentialSubjectType
	newleaf("1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962"),  // credentialSchemaType
	newleaf("12891444986491254085560597052395677934694594587847693550621945641098238258096", "870222225577550446142292957325790690140780476504858538425256779240825462837"),  // credentialStatusType
	newleaf("14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370"), // typeID1
	newleaf("18943208076435454904128050626016920086499867123501959273334294100443438004188", "2038038677412689124034084719683107814279606773706261227437666149072023632255"), // typeDI2
	newleaf("2282658739689398501857830040602888548545380116161185117921371325237897538551", "9033719693259832177439488944502349301386207418184651337843275979338597322540"),  // credentialSchemaID
}

var updateTemplate = []leaf{
	newleaf("5213439259676021610106577921037707268541764175155543794420152605023181390139", "0"),  // birthday
	newleaf("1479963091211635594734723538545884456894938414357497418097512533895772796527", "0"),  // gender
	newleaf("19238944412824247341353086074402759833940010832364197352719874011476854540013", "0"), // pincode
	newleaf("14522734804373614041942549305708452359006179872334741006179415532376146140639", "0"), // state
	newleaf("1763085948543522232029667616550496120517967703023484347613954302553484294902", "0"),  // revocationNonce
	newleaf("11896622783611378286548274235251973588039499084629981048616800443645803129554", "0"), // credentialStatusID
	newleaf("4792130079462681165428511201253235850015648352883240577315026477780493110675", "0"),  // credentialSubjectID
	newleaf("13483382060079230067188057675928039600565406666878111320562435194759310415773", "0"), // expirationDate
	newleaf("8713837106709436881047310678745516714551061952618778897121563913918335939585", "0"),  // issuanceDate
	newleaf("5940025296598751562822259677636111513267244048295724788691376971035167813215", "0"),  // issuer
}

type updateValues struct {
	Birthday            *big.Int
	Gender              *big.Int
	Pincode             *big.Int
	State               *big.Int
	RevocationNonce     *big.Int
	CredentialStatusID  *big.Int
	CredentialSubjectID *big.Int
	ExpirationDate      *big.Int
	IssuanceDate        *big.Int
	Issuer              *big.Int
}

func (u *updateValues) toList() []*big.Int {
	return []*big.Int{
		u.Birthday,
		u.Gender,
		u.Pincode,
		u.State,
		u.RevocationNonce,
		u.CredentialStatusID,
		u.CredentialSubjectID,
		u.ExpirationDate,
		u.IssuanceDate,
		u.Issuer,
	}
}

type templateTree struct {
	tree *merkletree.MerkleTree
}

func newTemplateTree() (*templateTree, error) {
	treeStorage := memory.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(context.Background(), treeStorage, treeLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create merkle tree: %w", err)
	}
	t := make([]leaf, len(template)+len(updateTemplate))
	copy(t, template)
	copy(t[len(template):], updateTemplate)

	for _, node := range t {
		err := mt.Add(context.Background(), node.key, node.value)
		if err != nil {
			return nil, fmt.Errorf("failed to add node to merkle tree: %w", err)
		}
	}
	return &templateTree{mt}, nil
}

func (t *templateTree) update(u updateValues) ([]*merkletree.CircomProcessorProof, error) {
	res := make([]*merkletree.CircomProcessorProof, 0, len(updateTemplate))
	values := u.toList()
	for i := range updateTemplate {
		p, err := t.tree.Update(context.Background(), updateTemplate[i].key, values[i])
		if err != nil {
			return nil, fmt.Errorf("failed to update node to merkle tree: %w", err)
		}
		res = append(res, p)
	}
	return res, nil
}

func (t *templateTree) root() *big.Int {
	return t.tree.Root().BigInt()
}

type leaf struct {
	key   *big.Int
	value *big.Int
}

func newleaf(key, value string) leaf {
	return leaf{mustBigInt(key), mustBigInt(value)}
}
